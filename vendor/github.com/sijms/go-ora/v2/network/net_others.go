//go:build !windows

package network

import (
	"errors"
	"net"
	"os"
	"syscall"
)

func sendOOB(conn net.Conn) (done bool, err error) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if remoteAddr, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
			var to syscall.Sockaddr
			if len(remoteAddr.IP) == 4 {
				temp := (*[4]byte)(remoteAddr.IP)
				to = &syscall.SockaddrInet4{
					Port: remoteAddr.Port,
					Addr: *temp,
				}
			} else {
				temp := (*[16]byte)(remoteAddr.IP)
				to = &syscall.SockaddrInet6{
					Port:   remoteAddr.Port,
					ZoneId: 0,
					Addr:   *temp,
				}
			}
			var file *os.File
			file, err = tcpConn.File()
			if err != nil {
				return
			}
			defer func(file *os.File) {
				_ = file.Close()
			}(file)
			err = syscall.Sendmsg(int(file.Fd()), nil, []byte{33}, to, syscall.MSG_OOB)
			if err != nil {
				return
			}
			done = true
			err = syscall.SetNonblock(int(file.Fd()), true)
		}
	} else {
		err = errors.New("not a tcp connection")
	}
	return
}
