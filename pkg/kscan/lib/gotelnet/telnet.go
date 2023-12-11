package gotelnet

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/lcvvvv/gonmap/lib/chinese"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	TIME_DELAY_AFTER_WRITE = 300 * time.Millisecond

	// Telnet protocol characters (don't change)
	IAC  = byte(255) // "Interpret As Command"
	DONT = byte(254)
	DO   = byte(253)
	WONT = byte(252)
	WILL = byte(251)
	SB   = byte(250) // Subnegotiation Begin
	SE   = byte(240) // Subnegotiation End

	NULL  = byte(0)
	EOF   = byte(236) // Document End
	SUSP  = byte(237) // Subnegotiation End
	ABORT = byte(238) // Process Stop
	REOR  = byte(239) // Record End
	NOP   = byte(241) // No Operation
	DM    = byte(242) // Data Mark
	BRK   = byte(243) // Break
	IP    = byte(244) // Interrupt process
	AO    = byte(245) // Abort output
	AYT   = byte(246) // Are You There
	EC    = byte(247) // Erase Character
	EL    = byte(248) // Erase Line
	GA    = byte(249) // Go Ahead

	// Telnet protocol options code (don't change)
	// These ones all come from arpa/telnet.h
	BINARY         = byte(0)  // 8-bit data path
	ECHO           = byte(1)  // echo
	RCP            = byte(2)  // prepare to reconnect
	SGA            = byte(3)  // suppress go ahead
	NAMS           = byte(4)  // approximate message size
	STATUS         = byte(5)  // give status
	TM             = byte(6)  // timing mark
	RCTE           = byte(7)  // remote controlled transmission and echo
	NAOL           = byte(8)  // negotiate about output line width
	NAOP           = byte(9)  // negotiate about output page size
	NAOCRD         = byte(10) // negotiate about CR disposition
	NAOHTS         = byte(11) // negotiate about horizontal tabstops
	NAOHTD         = byte(12) // negotiate about horizontal tab disposition
	NAOFFD         = byte(13) // negotiate about formfeed disposition
	NAOVTS         = byte(14) // negotiate about vertical tab stops
	NAOVTD         = byte(15) // negotiate about vertical tab disposition
	NAOLFD         = byte(16) // negotiate about output LF disposition
	XASCII         = byte(17) // extended ascii character set
	LOGOUT         = byte(18) // force logout
	BM             = byte(19) // byte macro
	DET            = byte(20) // data entry terminal
	SUPDUP         = byte(21) // supdup protocol
	SUPDUPOUTPUT   = byte(22) // supdup output
	SNDLOC         = byte(23) // send location
	TTYPE          = byte(24) // terminal type
	EOR            = byte(25) // end or record
	TUID           = byte(26) // TACACS user identification
	OUTMRK         = byte(27) // output marking
	TTYLOC         = byte(28) // terminal location number
	VT3270REGIME   = byte(29) // 3270 regime
	X3PAD          = byte(30) // X.3 PAD
	NAWS           = byte(31) // window size
	TSPEED         = byte(32) // terminal speed
	LFLOW          = byte(33) // remote flow control
	LINEMODE       = byte(34) // Linemode option
	XDISPLOC       = byte(35) // X Display Location
	OLD_ENVIRON    = byte(36) // Old - Environment variables
	AUTHENTICATION = byte(37) // Authenticate
	ENCRYPT        = byte(38) // Encryption option
	NEW_ENVIRON    = byte(39) // New - Environment variables
	// the following ones come from
	// http://www.iana.org/assignments/telnet-options
	// Unfortunately, that document does not assign identifiers
	// to all of them, so we are making them up
	TN3270E             = byte(40)  // TN3270E
	XAUTH               = byte(41)  // XAUTH
	CHARSET             = byte(42)  // CHARSET
	RSP                 = byte(43)  // Telnet Remote Serial Port
	COM_PORT_OPTION     = byte(44)  // Com Port Control Option
	SUPPRESS_LOCAL_ECHO = byte(45)  // Telnet Suppress Local Echo
	TLS                 = byte(46)  // Telnet Start TLS
	KERMIT              = byte(47)  // KERMIT
	SEND_URL            = byte(48)  // SEND-URL
	FORWARD_X           = byte(49)  // FORWARD_X
	PRAGMA_LOGON        = byte(138) // TELOPT PRAGMA LOGON
	SSPI_LOGON          = byte(139) // TELOPT SSPI LOGON
	PRAGMA_HEARTBEAT    = byte(140) // TELOPT PRAGMA HEARTBEAT
	EXOPL               = byte(255) // Extended-Options-List
	NOOPT               = byte(0)
)

const (
	Closed = iota
	UnauthorizedAccess
	OnlyPassword
	UsernameAndPassword
)

type Client struct {
	IPAddr       string
	Port         int
	UserName     string
	Password     string
	conn         net.Conn
	LastResponse string
	ServerType   int
}

func New(addr string, port int) *Client {
	return &Client{
		IPAddr:       addr,
		Port:         port,
		UserName:     "",
		Password:     "",
		conn:         nil,
		LastResponse: "",
		ServerType:   0,
	}
}

func (c *Client) Connect() error {
	conn, err := net.DialTimeout("tcp", c.Netloc(), 5*time.Second)
	if err != nil {
		return err
	}
	c.conn = conn
	//开启输入监听
	go func() {
		for {
			buf, err := c.read()
			if err != nil {
				if util.StrContains(err.Error(), "closed") {
					break
				}
				if util.StrContains(err.Error(), "EOF") {
					break
				}
				//slog.Printf(slog.WARN, "%v:%v,telnet read is err:%v,", c.IPAddr, c.Port, err)
				break
			}
			displayBuf, commandList := c.SerializationResponse(buf)
			if len(commandList) > 0 {
				replyBuf := c.MakeReplyFromList(commandList)
				c.LastResponse += string(displayBuf)
				_ = c.write(replyBuf)
			} else {
				c.LastResponse += string(displayBuf)
			}
		}
	}()
	//等待初始化
	time.Sleep(time.Second * 3)
	return nil
}

func (c *Client) WriteContext(s string) {
	_ = c.write([]byte(s + "\x0d\x00"))
}

func (c *Client) ReadContext() string {
	defer func() { c.Clear() }() //结束时，清空输出内容
	if c.LastResponse == "" {
		time.Sleep(time.Second)
	}
	c.LastResponse = strings.ReplaceAll(c.LastResponse, "\x0d\x00", "")
	c.LastResponse = strings.ReplaceAll(c.LastResponse, "\x0d\x0a", "\n")
	c.LastResponse = chinese.ToUTF8(c.LastResponse)
	return c.LastResponse
}

func (c *Client) Netloc() string {
	return fmt.Sprintf("%s:%d", c.IPAddr, c.Port)
}

func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) SerializationResponse(responseBuf []byte) (displayBuf []byte, commandList [][]byte) {
	for {
		index := bytes.IndexByte(responseBuf, IAC)
		if index == -1 {
			displayBuf = append(displayBuf, responseBuf...)
			break
		}
		if len(responseBuf)-index < 2 {
			displayBuf = append(displayBuf, responseBuf...)
			break
		}
		//获取选项字符
		ch := responseBuf[index+1]
		if ch == IAC {
			//将以IAC 开头之前的字符，赋值给最终显示文字
			displayBuf = append(displayBuf, responseBuf[:index]...)
			//将处理过的字符串删去
			responseBuf = responseBuf[index+1:]
			continue
		}
		if ch == DO || ch == DONT || ch == WILL || ch == WONT {
			IACBuf := responseBuf[index : index+3]
			//将以IAC 开头3个字符组成的整个命令存储起来
			commandList = append(commandList, IACBuf)
			//将以IAC 开头之前的字符，赋值给最终显示文字
			displayBuf = append(displayBuf, responseBuf[:index]...)
			//将处理过的字符串删去
			responseBuf = responseBuf[index+3:]
			continue
		}
		if ch == SB {
			//将以IAC 开头之前的字符，赋值给最终显示文字
			displayBuf = append(displayBuf, responseBuf[:index]...)
			//获取SE 结束字符位置
			seIndex := bytes.IndexByte(responseBuf, SE)
			//将以IAC 开头SB至SE的子协商存储起来
			commandList = append(commandList, responseBuf[index:seIndex])
			//将处理过的字符串删去
			responseBuf = responseBuf[seIndex+1:]
			continue
		}
		break
	}
	return displayBuf, commandList
}

func (c *Client) MakeReplyFromList(list [][]byte) []byte {
	var reply []byte
	for _, command := range list {
		reply = append(reply, c.MakeReply(command)...)
	}
	return reply
}

func (c *Client) MakeReply(command []byte) []byte {
	if len(command) < 3 {
		return []byte{}
	}
	verb := command[1]
	option := command[2]

	//如果选项码为 回显(1) 或者是抑制继续进行(3)
	if option == ECHO {
		if verb == DO {
			return []byte{IAC, WILL, option}
		}
		if verb == DONT {
			return []byte{IAC, WONT, option}
		}
		if verb == WILL {
			return []byte{IAC, DO, option}
		}
		if verb == WONT {
			return []byte{IAC, DONT, option}
		}
		if verb == SB {
			/*
			 * 因为启动了子标志位,命令长度扩展到了4字节,
			 * 取最后一个标志字节为选项码
			 * 如果这个选项码字节为1(send)
			 * 则回发为 250(SB子选项开始) + 获取的第二个字节 + 0(is) + 255(标志位IAC) + 240(SE子选项结束)
			 */
			modifier := command[3]
			if modifier == ECHO {
				return []byte{IAC, SB, option, BINARY, IAC, SE}
			}
		}
	} else if option == SGA {
		if verb == DO {
			return []byte{IAC, WILL, option}
		}
		if verb == DONT {
			return []byte{IAC, WONT, option}
		}
		if verb == WILL {
			return []byte{IAC, DO, option}
		}
		if verb == WONT {
			return []byte{IAC, DONT, option}
		}
		if verb == SB {
			/*
			 * 因为启动了子标志位,命令长度扩展到了4字节,
			 * 取最后一个标志字节为选项码
			 * 如果这个选项码字节为1(send)
			 * 则回发为 250(SB子选项开始) + 获取的第二个字节 + 0(is) + 255(标志位IAC) + 240(SE子选项结束)
			 */
			modifier := command[3]
			if modifier == ECHO {
				return []byte{IAC, SB, option, BINARY, IAC, SE}
			}
		}
	} else {
		if verb == DO {
			return []byte{IAC, WONT, option}
		}
		if verb == DONT {
			return []byte{IAC, WONT, option}
		}
		if verb == WILL {
			return []byte{IAC, DONT, option}
		}
		if verb == WONT {
			return []byte{IAC, DONT, option}
		}
	}
	return []byte{}
}

func (c *Client) read() ([]byte, error) {
	var buf [2048]byte
	var n int
	//_ = c.conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	n, err := c.conn.Read(buf[0:])
	if err != nil {
		return nil, err
	}
	//slog.Println(slog.DEBUG, buf[:n], "-<<<<<<<<")
	return buf[:n], nil
}

func (c *Client) write(buf []byte) error {
	//slog.Println(slog.DEBUG, ">>>>>>>>>-", buf)
	_ = c.conn.SetWriteDeadline(time.Now().Add(time.Second * 3))
	_, err := c.conn.Write(buf)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) Login() error {
	switch c.ServerType {
	case Closed:
		return errors.New("service is disabled")
	case UnauthorizedAccess:
		return nil
	case OnlyPassword:
		return c.loginForOnlyPassword()
	case UsernameAndPassword:
		return c.loginForUsernameAndPassword()
	}
	return errors.New("unknown server type")
}

func (c *Client) MakeServerType() int {
	responseString := c.ReadContext()
	response := strings.Split(responseString, "\n")
	lastLine := response[len(response)-1]
	lastLine = strings.ToLower(lastLine)
	if util.StrContains(lastLine, "user") || util.StrContains(lastLine, "name") || util.StrContains(lastLine, "login") || util.StrContains(lastLine, "account") || strings.Contains(lastLine, "用户名") || strings.Contains(lastLine, "登录") {
		//slog.Printf(slog.INFO, "%v:%v,telnet mode is : usernameAndPassword ,response is :%v", c.IPAddr, c.Port, lastLine)
		return UsernameAndPassword
	}
	if util.StrContains(lastLine, "pass") {
		//slog.Printf(slog.INFO, "%v:%v,telnet mode is : onlyPassword ,response is :%v", c.IPAddr, c.Port, lastLine)
		return OnlyPassword
	}
	if regexp.MustCompile(`^/ #.*`).MatchString(lastLine) {
		return UnauthorizedAccess
	}
	if regexp.MustCompile(`^<[A-Za-z0-9_]+>`).MatchString(lastLine) {
		return UnauthorizedAccess
	}
	if regexp.MustCompile(`^#`).MatchString(lastLine) {
		return UnauthorizedAccess
	}

	if c.isLoginSucceed(responseString) {
		return UnauthorizedAccess
	}

	//slog.Printf(slog.WARN, "%v:%v,telnet mode is : unknown ,response is :%v", c.IPAddr, c.Port, lastLine)
	return Closed
}

func (c *Client) loginForOnlyPassword() error {
	c.Clear()
	//清空一次输出
	c.WriteContext(c.Password)
	time.Sleep(time.Second * 3)

	responseString := c.ReadContext()
	if c.isLoginFailed(responseString) {
		return errors.New("login failed")
	}

	if c.isLoginSucceed(responseString) {
		return nil
	}

	//slog.Println(slog.WARN, c.IPAddr, c.Port, "|", responseString)
	return errors.New("login failed")

}

func (c *Client) loginForUsernameAndPassword() error {
	c.WriteContext(c.UserName)
	time.Sleep(time.Second * 3)
	c.Clear() //清空一次输出
	c.WriteContext(c.Password)
	time.Sleep(time.Second * 5)

	responseString := c.ReadContext()
	if c.isLoginFailed(responseString) {
		return errors.New("login failed")
	}
	if c.isLoginSucceed(responseString) {
		return nil
	}
	//slog.Println(slog.WARN, c.IPAddr, c.Port, "|", responseString)
	return errors.New("login failed")
}

func (c *Client) Clear() {
	c.LastResponse = ""
}

var loginFailedString = []string{
	"wrong",
	"invalid",
	"fail",
	"incorrect",
	"error",
}

func (c *Client) isLoginFailed(responseString string) bool {
	responseString = strings.ToLower(responseString)
	if responseString == "" {
		return true
	}
	for _, str := range loginFailedString {
		if strings.Contains(responseString, str) {
			return true
		}
	}
	if regexp.MustCompile("(?is).*pass(word)?:$").MatchString(responseString) {
		return true
	}
	if regexp.MustCompile("(?is).*user(name)?:$").MatchString(responseString) {
		return true
	}
	if regexp.MustCompile("(?is).*login:$").MatchString(responseString) {
		return true
	}
	return false
}

func (c *Client) isLoginSucceed(responseString string) bool {
	responseStringArray := strings.Split(responseString, "\n")
	lastLine := responseStringArray[len(responseStringArray)-1]
	if regexp.MustCompile("^[#$].*").MatchString(lastLine) {
		return true
	}
	if regexp.MustCompile("^<[a-zA-Z0-9_]+>.*").MatchString(lastLine) {
		return true
	}
	if regexp.MustCompile("(?:s)last login").MatchString(responseString) {
		return true
	}
	c.Clear()
	c.WriteContext("?")
	time.Sleep(time.Second * 3)
	responseString = c.ReadContext()
	if strings.Count(responseString, "\n") > 6 {
		//slog.Println(slog.WARN, "3|", c.IPAddr, c.Port, responseString)
		return true
	}
	if len([]rune(responseString)) > 100 {
		//slog.Println(slog.WARN, "4|", c.IPAddr, c.Port, responseString)
		return true
	}
	return false
}
