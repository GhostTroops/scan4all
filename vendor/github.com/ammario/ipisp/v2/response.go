package ipisp

import (
	"net"
	"time"
)

// Response contains a response from Cymru.
type Response struct {
	IP          net.IP
	ASN         ASN
	ISPName     string
	Country     string
	Registry    string
	Range       *net.IPNet
	AllocatedAt time.Time
}
