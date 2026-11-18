package weblogic

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// T3Client WebLogic T3 协议客户端
type T3Client struct {
	Host    string
	Port    int
	Timeout time.Duration
	Version string
	conn    net.Conn
	reader  *bufio.Reader
}

func NewT3Client(host string, port int, timeout time.Duration) *T3Client {
	return &T3Client{Host: host, Port: port, Timeout: timeout}
}

func (t *T3Client) Connect() error {
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	conn, err := net.DialTimeout("tcp", addr, t.Timeout)
	if err != nil {
		return fmt.Errorf("TCP连接失败: %w", err)
	}
	t.conn = conn
	t.conn.SetDeadline(time.Now().Add(t.Timeout))
	t.reader = bufio.NewReader(conn)

	handshake := "t3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n"
	if _, err = t.conn.Write([]byte(handshake)); err != nil {
		t.conn.Close()
		return fmt.Errorf("发送握手失败: %w", err)
	}

	resp, err := t.reader.ReadString('\n')
	if err != nil {
		t.conn.Close()
		return fmt.Errorf("读取握手响应失败: %w", err)
	}
	if !strings.HasPrefix(resp, "HELO:") {
		t.conn.Close()
		return fmt.Errorf("非WebLogic T3服务")
	}
	t.Version = strings.TrimSpace(strings.TrimPrefix(resp, "HELO:"))
	return nil
}

func (t *T3Client) Close() {
	if t.conn != nil {
		t.conn.Close()
	}
}

// SendT3Message 发送 T3 消息并读取响应
func (t *T3Client) SendT3Message(msgType int32, payload []byte) ([]byte, error) {
	header := make([]byte, 8)
	msgLen := int32(len(payload) + 4)
	header[0] = byte(msgLen >> 24)
	header[1] = byte(msgLen >> 16)
	header[2] = byte(msgLen >> 8)
	header[3] = byte(msgLen)
	header[4] = byte(msgType >> 24)
	header[5] = byte(msgType >> 16)
	header[6] = byte(msgType >> 8)
	header[7] = byte(msgType)
	data := append(header, payload...)
	if _, err := t.conn.Write(data); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := t.reader.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (t *T3Client) Detect() (string, error) {
	if err := t.Connect(); err != nil {
		return "", err
	}
	defer t.Close()
	return t.Version, nil
}

// CheckVersionVulnerable 检查版本是否在受影响范围内
func CheckVersionVulnerable(version, cve string) bool {
	v := NormalizeVersion(version)
	affected := map[string][]string{
		"CVE-2018-2628":  {"10.3.6.0", "12.1.3.0", "12.2.1.0", "12.2.1.1", "12.2.1.2", "12.2.1.3"},
		"CVE-2026-70748": {"12.2.1.3", "12.2.1.4", "14.1.1.0", "14.1.2.0", "15.1.1.0"},
		"CVE-2026-60672": {"12.2.1.3", "12.2.1.4", "14.1.1.0", "14.1.2.0"},
		"CVE-2026-35301": {"12.2.1.3", "12.2.1.4", "14.1.1.0"},
		"CVE-2023-21839": {"12.2.1.3", "12.2.1.4", "14.1.1.0"},
	}
	for _, a := range affected[cve] {
		if strings.HasPrefix(v, a) {
			return true
		}
	}
	return false
}

// IsValidVersion 检查是否为合法 WebLogic 版本
func IsValidVersion(v string) bool {
	v = NormalizeVersion(v)
	if v == "" || v == "0.0.0.0" || v == "0.0.0" {
		return false
	}
	for _, p := range []string{"10.3.6", "12.1.3", "12.2.1", "14.1.1", "14.1.2", "15.1.1"} {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	return false
}

func NormalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	re := regexp.MustCompile(`[\d.]+`)
	return re.FindString(v)
}

// ExtractHostnameFromBytes 从二进制响应中提取可打印 hostname
func ExtractHostnameFromBytes(data []byte) string {
	var printable []byte
	for _, b := range data {
		if b >= 32 && b <= 126 || b == '\n' || b == '\r' || b == '\t' {
			printable = append(printable, b)
		}
	}
	s := strings.TrimSpace(string(printable))
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.Contains(line, "HTTP") && !strings.Contains(line, "HELO") && len(line) < 256 {
			return line
		}
	}
	return s
}
