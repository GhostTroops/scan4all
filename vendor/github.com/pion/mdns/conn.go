// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"context"
	"errors"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/pion/logging"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

// Conn represents a mDNS Server
type Conn struct {
	mu  sync.RWMutex
	log logging.LeveledLogger

	socket  *ipv4.PacketConn
	dstAddr *net.UDPAddr

	queryInterval time.Duration
	localNames    []string
	queries       []query
	ifaces        []net.Interface

	closed chan interface{}
}

type query struct {
	nameWithSuffix  string
	queryResultChan chan queryResult
}

type queryResult struct {
	answer dnsmessage.ResourceHeader
	addr   net.Addr
}

const (
	defaultQueryInterval = time.Second
	destinationAddress   = "224.0.0.251:5353"
	maxMessageRecords    = 3
	responseTTL          = 120
)

var errNoPositiveMTUFound = errors.New("no positive MTU found")

// Server establishes a mDNS connection over an existing conn
func Server(conn *ipv4.PacketConn, config *Config) (*Conn, error) {
	if config == nil {
		return nil, errNilConfig
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	inboundBufferSize := 0
	joinErrCount := 0
	ifacesToUse := make([]net.Interface, 0, len(ifaces))
	for i, ifc := range ifaces {
		if err = conn.JoinGroup(&ifaces[i], &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251)}); err != nil {
			joinErrCount++
			continue
		}

		ifcCopy := ifc
		ifacesToUse = append(ifacesToUse, ifcCopy)
		if ifaces[i].MTU > inboundBufferSize {
			inboundBufferSize = ifaces[i].MTU
		}
	}

	if inboundBufferSize == 0 {
		return nil, errNoPositiveMTUFound
	}
	if joinErrCount >= len(ifaces) {
		return nil, errJoiningMulticastGroup
	}

	dstAddr, err := net.ResolveUDPAddr("udp", destinationAddress)
	if err != nil {
		return nil, err
	}

	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	localNames := []string{}
	for _, l := range config.LocalNames {
		localNames = append(localNames, l+".")
	}

	c := &Conn{
		queryInterval: defaultQueryInterval,
		queries:       []query{},
		socket:        conn,
		dstAddr:       dstAddr,
		localNames:    localNames,
		ifaces:        ifacesToUse,
		log:           loggerFactory.NewLogger("mdns"),
		closed:        make(chan interface{}),
	}
	if config.QueryInterval != 0 {
		c.queryInterval = config.QueryInterval
	}

	if err := conn.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		c.log.Warnf("Failed to SetControlMessage on PacketConn %v", err)
	}

	// https://www.rfc-editor.org/rfc/rfc6762.html#section-17
	// Multicast DNS messages carried by UDP may be up to the IP MTU of the
	// physical interface, less the space required for the IP header (20
	// bytes for IPv4; 40 bytes for IPv6) and the UDP header (8 bytes).
	go c.start(inboundBufferSize-20-8, config)
	return c, nil
}

// Close closes the mDNS Conn
func (c *Conn) Close() error {
	select {
	case <-c.closed:
		return nil
	default:
	}

	if err := c.socket.Close(); err != nil {
		return err
	}

	<-c.closed
	return nil
}

// Query sends mDNS Queries for the following name until
// either the Context is canceled/expires or we get a result
func (c *Conn) Query(ctx context.Context, name string) (dnsmessage.ResourceHeader, net.Addr, error) {
	select {
	case <-c.closed:
		return dnsmessage.ResourceHeader{}, nil, errConnectionClosed
	default:
	}

	nameWithSuffix := name + "."

	queryChan := make(chan queryResult, 1)
	c.mu.Lock()
	c.queries = append(c.queries, query{nameWithSuffix, queryChan})
	ticker := time.NewTicker(c.queryInterval)
	c.mu.Unlock()

	defer ticker.Stop()

	c.sendQuestion(nameWithSuffix)
	for {
		select {
		case <-ticker.C:
			c.sendQuestion(nameWithSuffix)
		case <-c.closed:
			return dnsmessage.ResourceHeader{}, nil, errConnectionClosed
		case res := <-queryChan:
			return res.answer, res.addr, nil
		case <-ctx.Done():
			return dnsmessage.ResourceHeader{}, nil, errContextElapsed
		}
	}
}

func ipToBytes(ip net.IP) (out [4]byte) {
	rawIP := ip.To4()
	if rawIP == nil {
		return
	}

	ipInt := big.NewInt(0)
	ipInt.SetBytes(rawIP)
	copy(out[:], ipInt.Bytes())
	return
}

func interfaceForRemote(remote string) (net.IP, error) {
	conn, err := net.Dial("udp", remote)
	if err != nil {
		return nil, err
	}

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errFailedCast
	}

	if err := conn.Close(); err != nil {
		return nil, err
	}

	return localAddr.IP, nil
}

func (c *Conn) sendQuestion(name string) {
	packedName, err := dnsmessage.NewName(name)
	if err != nil {
		c.log.Warnf("Failed to construct mDNS packet %v", err)
		return
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{},
		Questions: []dnsmessage.Question{
			{
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				Name:  packedName,
			},
		},
	}

	rawQuery, err := msg.Pack()
	if err != nil {
		c.log.Warnf("Failed to construct mDNS packet %v", err)
		return
	}

	c.writeToSocket(0, rawQuery, false)
}

func (c *Conn) writeToSocket(ifIndex int, b []byte, onlyLooback bool) {
	if ifIndex != 0 {
		ifc, err := net.InterfaceByIndex(ifIndex)
		if err != nil {
			c.log.Warnf("Failed to get interface interface for %d: %v", ifIndex, err)
			return
		}
		if onlyLooback && ifc.Flags&net.FlagLoopback == 0 {
			// avoid accidentally tricking the destination that itself is the same as us
			c.log.Warnf("Interface is not loopback %d", ifIndex)
			return
		}
		if err := c.socket.SetMulticastInterface(ifc); err != nil {
			c.log.Warnf("Failed to set multicast interface for %d: %v", ifIndex, err)
		} else {
			if _, err := c.socket.WriteTo(b, nil, c.dstAddr); err != nil {
				c.log.Warnf("Failed to send mDNS packet on interface %d: %v", ifIndex, err)
			}
		}
		return
	}
	for ifcIdx := range c.ifaces {
		if onlyLooback && c.ifaces[ifcIdx].Flags&net.FlagLoopback == 0 {
			// avoid accidentally tricking the destination that itself is the same as us
			continue
		}
		if err := c.socket.SetMulticastInterface(&c.ifaces[ifcIdx]); err != nil {
			c.log.Warnf("Failed to set multicast interface for %d: %v", c.ifaces[ifcIdx].Index, err)
		} else {
			if _, err := c.socket.WriteTo(b, nil, c.dstAddr); err != nil {
				c.log.Warnf("Failed to send mDNS packet on interface %d: %v", c.ifaces[ifcIdx].Index, err)
			}
		}
	}
}

func (c *Conn) sendAnswer(name string, ifIndex int, dst net.IP) {
	packedName, err := dnsmessage.NewName(name)
	if err != nil {
		c.log.Warnf("Failed to construct mDNS packet %v", err)
		return
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:      true,
			Authoritative: true,
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					Name:  packedName,
					TTL:   responseTTL,
				},
				Body: &dnsmessage.AResource{
					A: ipToBytes(dst),
				},
			},
		},
	}

	rawAnswer, err := msg.Pack()
	if err != nil {
		c.log.Warnf("Failed to construct mDNS packet %v", err)
		return
	}

	c.writeToSocket(ifIndex, rawAnswer, dst.IsLoopback())
}

func (c *Conn) start(inboundBufferSize int, config *Config) { //nolint gocognit
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		close(c.closed)
	}()

	b := make([]byte, inboundBufferSize)
	p := dnsmessage.Parser{}

	for {
		n, cm, src, err := c.socket.ReadFrom(b)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			c.log.Warnf("Failed to ReadFrom %q %v", src, err)
			continue
		}
		var ifIndex int
		if cm != nil {
			ifIndex = cm.IfIndex
		}

		func() {
			c.mu.RLock()
			defer c.mu.RUnlock()

			if _, err := p.Start(b[:n]); err != nil {
				c.log.Warnf("Failed to parse mDNS packet %v", err)
				return
			}

			for i := 0; i <= maxMessageRecords; i++ {
				q, err := p.Question()
				if errors.Is(err, dnsmessage.ErrSectionDone) {
					break
				} else if err != nil {
					c.log.Warnf("Failed to parse mDNS packet %v", err)
					return
				}

				for _, localName := range c.localNames {
					if localName == q.Name.String() {
						if config.LocalAddress != nil {
							c.sendAnswer(q.Name.String(), ifIndex, config.LocalAddress)
						} else {
							localAddress, err := interfaceForRemote(src.String())
							if err != nil {
								c.log.Warnf("Failed to get local interface to communicate with %s: %v", src.String(), err)
								continue
							}

							c.sendAnswer(q.Name.String(), ifIndex, localAddress)
						}
					}
				}
			}

			for i := 0; i <= maxMessageRecords; i++ {
				a, err := p.AnswerHeader()
				if errors.Is(err, dnsmessage.ErrSectionDone) {
					return
				}
				if err != nil {
					c.log.Warnf("Failed to parse mDNS packet %v", err)
					return
				}

				if a.Type != dnsmessage.TypeA && a.Type != dnsmessage.TypeAAAA {
					continue
				}

				for i := len(c.queries) - 1; i >= 0; i-- {
					if c.queries[i].nameWithSuffix == a.Name.String() {
						ip, err := ipFromAnswerHeader(a, p)
						if err != nil {
							c.log.Warnf("Failed to parse mDNS answer %v", err)
							return
						}

						c.queries[i].queryResultChan <- queryResult{a, &net.IPAddr{
							IP: ip,
						}}
						c.queries = append(c.queries[:i], c.queries[i+1:]...)
					}
				}
			}
		}()
	}
}

func ipFromAnswerHeader(a dnsmessage.ResourceHeader, p dnsmessage.Parser) (ip []byte, err error) {
	if a.Type == dnsmessage.TypeA {
		resource, err := p.AResource()
		if err != nil {
			return nil, err
		}
		ip = net.IP(resource.A[:])
	} else {
		resource, err := p.AAAAResource()
		if err != nil {
			return nil, err
		}
		ip = resource.AAAA[:]
	}

	return
}
