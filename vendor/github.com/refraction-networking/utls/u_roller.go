package tls

import (
	"net"
	"sync"
	"time"
)

type Roller struct {
	HelloIDs            []ClientHelloID
	HelloIDMu           sync.Mutex
	WorkingHelloID      *ClientHelloID
	TcpDialTimeout      time.Duration
	TlsHandshakeTimeout time.Duration
	r                   *prng
}

// NewRoller creates Roller object with default range of HelloIDs to cycle through until a
// working/unblocked one is found.
func NewRoller() (*Roller, error) {
	r, err := newPRNG()
	if err != nil {
		return nil, err
	}

	tcpDialTimeoutInc := r.Intn(14)
	tcpDialTimeoutInc = 7 + tcpDialTimeoutInc

	tlsHandshakeTimeoutInc := r.Intn(20)
	tlsHandshakeTimeoutInc = 11 + tlsHandshakeTimeoutInc

	return &Roller{
		HelloIDs: []ClientHelloID{
			HelloChrome_Auto,
			HelloFirefox_Auto,
			HelloIOS_Auto,
			HelloRandomized,
		},
		TcpDialTimeout:      time.Second * time.Duration(tcpDialTimeoutInc),
		TlsHandshakeTimeout: time.Second * time.Duration(tlsHandshakeTimeoutInc),
		r:                   r,
	}, nil
}

// Dial attempts to establish connection to given address using different HelloIDs.
// If a working HelloID is found, it is used again for subsequent Dials.
// If tcp connection fails or all HelloIDs are tried, returns with last error.
//
// Usage examples:
//    Dial("tcp4", "google.com:443", "google.com")
//    Dial("tcp", "10.23.144.22:443", "mywebserver.org")
func (c *Roller) Dial(network, addr, serverName string) (*UConn, error) {
	helloIDs := make([]ClientHelloID, len(c.HelloIDs))
	copy(helloIDs, c.HelloIDs)
	c.r.rand.Shuffle(len(c.HelloIDs), func(i, j int) {
		helloIDs[i], helloIDs[j] = helloIDs[j], helloIDs[i]
	})

	c.HelloIDMu.Lock()
	workingHelloId := c.WorkingHelloID // keep using same helloID, if it works
	c.HelloIDMu.Unlock()
	if workingHelloId != nil {
		helloIDFound := false
		for i, ID := range helloIDs {
			if ID == *workingHelloId {
				helloIDs[i] = helloIDs[0]
				helloIDs[0] = *workingHelloId // push working hello ID first
				helloIDFound = true
				break
			}
		}
		if !helloIDFound {
			helloIDs = append([]ClientHelloID{*workingHelloId}, helloIDs...)
		}
	}

	var tcpConn net.Conn
	var err error
	for _, helloID := range helloIDs {
		tcpConn, err = net.DialTimeout(network, addr, c.TcpDialTimeout)
		if err != nil {
			return nil, err // on tcp Dial failure return with error right away
		}

		client := UClient(tcpConn, nil, helloID)
		client.SetSNI(serverName)
		client.SetDeadline(time.Now().Add(c.TlsHandshakeTimeout))
		err = client.Handshake()
		client.SetDeadline(time.Time{}) // unset timeout
		if err != nil {
			continue // on tls Dial error keep trying HelloIDs
		}

		c.HelloIDMu.Lock()
		c.WorkingHelloID = &client.ClientHelloID
		c.HelloIDMu.Unlock()
		return client, err
	}
	return nil, err
}
