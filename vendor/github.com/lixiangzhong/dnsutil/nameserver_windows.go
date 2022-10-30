// +build windows

package dnsutil

import (
	"errors"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func nameserver() (string, error) {
	var b []byte
	l := uint32(15000) // recommended initial size
	for {
		b = make([]byte, l)
		err := windows.GetAdaptersAddresses(syscall.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &l)
		if err == nil {
			if l == 0 {
				return "", errors.New("nameserver: can't getadaptersaddresses")
			}
			break
		}
		if err.(syscall.Errno) != syscall.ERROR_BUFFER_OVERFLOW {
			return "", os.NewSyscallError("getadaptersaddresses", err)
		}
		if l <= uint32(len(b)) {
			return "", os.NewSyscallError("getadaptersaddresses", err)
		}
	}
	var aas []*windows.IpAdapterAddresses
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); aa != nil; aa = aa.Next {
		aas = append(aas, aa)
	}
	for _, v := range aas {
		return v.FirstDnsServerAddress.Address.IP().String(), nil
	}
	return "", errors.New("nameserver: can't getadaptersaddresses")
}
