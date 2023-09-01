//go:build windows

package network

import (
	"net"
)

func sendOOB(conn net.Conn) (done bool, err error) {
	return
	//if tcpConn, ok := conn.(*net.TCPConn); ok {
	//	if remoteAddr, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
	//		var to syscall.Sockaddr
	//		if len(remoteAddr.IP) == 4 {
	//			temp := (*[4]byte)(remoteAddr.IP)
	//			to = &syscall.SockaddrInet4{
	//				Port: remoteAddr.Port,
	//				Addr: *temp,
	//			}
	//		} else {
	//			temp := (*[16]byte)(remoteAddr.IP)
	//			to = &syscall.SockaddrInet6{
	//				Port:   remoteAddr.Port,
	//				ZoneId: 0,
	//				Addr:   *temp,
	//			}
	//		}
	//		var file *os.File
	//		file, err = tcpConn.File()
	//		if err != nil {
	//			return
	//		}
	//		defer func(file *os.File) {
	//			_ = file.Close()
	//		}(file)
	//		var sent uint32
	//		var buf = syscall.WSABuf{Len: 1, Buf: &[]byte{33}[0]}
	//
	//		err = syscall.WSASendto(syscall.Handle(file.Fd()), &buf, 1, &sent, 1, to, nil, nil)
	//		if err != nil {
	//			return
	//		}
	//		done = true
	//		err = syscall.SetNonblock(syscall.Handle(file.Fd()), true)
	//	}
	//} else {
	//	err = errors.New("not a tcp connection")
	//}
	//return
}
