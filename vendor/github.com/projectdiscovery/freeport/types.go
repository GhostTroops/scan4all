package freeport

// Protocol represents the supported protocol type
type Protocol uint8

const (
	TCP Protocol = iota
	UDP
)

// Port obtained from the kernel
type Port struct {
	Address  string
	Port     int
	Protocol Protocol
}
