package jndi

import (
	"encoding/hex"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"net"
	"time"
)

var JndiAddress string

var JndiLog []string

// 初始化变量
func init() {
	util.RegInitFunc(func() {
		JndiAddress = util.GetVal("JndiAddress")
	})
}

type Server struct {
	TcpListen *net.TCPListener
}

type Conn struct {
	TcpConn *net.TCPConn
}

func NewLdapServer() *Server {
	serverSocket := new(Server)
	return serverSocket
}

func NewWithPort(address string) (*Server, error) {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}
	addr, err = net.ResolveTCPAddr("tcp", fmt.Sprintf("0.0.0.0:%d", addr.Port))
	if err != nil {
		return nil, err
	}
	tcp, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, err
	}
	serverSocket := Server{tcp}
	return &serverSocket, nil
}

func (s *Server) Accept() *Conn {
	server, _ := s.TcpListen.AcceptTCP()
	return &Conn{TcpConn: server}
}

func (s *Server) Bind(addr net.TCPAddr) error {
	tcp, err := net.ListenTCP("tcp", &addr)
	if err != nil {
		return err
	}
	s.TcpListen = tcp
	return nil
}

func (s *Server) Close() {
	s.TcpListen.Close()
}

func (s *Server) GetInetAddress() net.Addr {
	return s.TcpListen.Addr()
}

func (s *Server) SetSoTimeout(timeout int) {
	duration := time.Duration(timeout)
	s.TcpListen.SetDeadline(time.Now().Add(duration * time.Millisecond))
}

func (conn Conn) parse() {
	data := make([]byte, 100)
	_, err := conn.TcpConn.Read(data)
	if err != nil {
		conn.TcpConn.Close()
		return
	}
	if data[0] == 0x4a && data[1] == 0x52 && data[2] == 0x4d && data[3] == 0x49 {
		conn.TcpConn.Write([]byte{0x4e, 0x00, 0x0d, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x32, 0x30, 0x33, 0x2e, 0x31, 0x00, 0x00, 0xd8, 0x7f})
		_, err = conn.TcpConn.Read(data)
		if err != nil {
			conn.TcpConn.Close()
			return
		}

	} else if data[0] == 0x30 && data[1] == 0x0c && data[2] == 0x02 && data[3] == 0x01 {
		conn.TcpConn.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
	}

	_, err = conn.TcpConn.Read(data)
	if err != nil {
		conn.TcpConn.Close()
		return
	}
	encodedStr := hex.EncodeToString(data[:])
	JndiLog = append(JndiLog, encodedStr)
	conn.TcpConn.Close()
}

func JndiServer() {
	if JndiAddress != "" {
		tcpListener, err := NewWithPort(JndiAddress)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer tcpListener.Close()
		for {
			c := tcpListener.Accept()
			go c.parse()
		}
	}
}
