package freeport

// Protocol represents the supported protocol type
type Protocol uint8

const (
	TCP Protocol = iota
	UDP
)

// Port obtained from the kernel
type Port struct {
	// Address is the address of the port (e.g. 127.0.0.1)
	Address string
	// Port is the port number
	Port int
	// Protocol is the protocol of the port (TCP or UDP)
	Protocol Protocol
	// Raw is the full OS listenable address (directly usable for net.Listen)
	NetListenAddress string
}
