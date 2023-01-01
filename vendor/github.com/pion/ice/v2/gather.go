package ice

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/logging"
	"github.com/pion/turn/v2"
)

const (
	stunGatherTimeout = time.Second * 5
)

type closeable interface {
	Close() error
}

// Close a net.Conn and log if we have a failure
func closeConnAndLog(c closeable, log logging.LeveledLogger, msg string) {
	if c == nil || (reflect.ValueOf(c).Kind() == reflect.Ptr && reflect.ValueOf(c).IsNil()) {
		log.Warnf("Conn is not allocated (%s)", msg)
		return
	}

	log.Warnf(msg)
	if err := c.Close(); err != nil {
		log.Warnf("Failed to close conn: %v", err)
	}
}

// fakePacketConn wraps a net.Conn and emulates net.PacketConn
type fakePacketConn struct {
	nextConn net.Conn
}

func (f *fakePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = f.nextConn.Read(p)
	addr = f.nextConn.RemoteAddr()
	return
}
func (f *fakePacketConn) Close() error                       { return f.nextConn.Close() }
func (f *fakePacketConn) LocalAddr() net.Addr                { return f.nextConn.LocalAddr() }
func (f *fakePacketConn) SetDeadline(t time.Time) error      { return f.nextConn.SetDeadline(t) }
func (f *fakePacketConn) SetReadDeadline(t time.Time) error  { return f.nextConn.SetReadDeadline(t) }
func (f *fakePacketConn) SetWriteDeadline(t time.Time) error { return f.nextConn.SetWriteDeadline(t) }
func (f *fakePacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return f.nextConn.Write(p)
}

// GatherCandidates initiates the trickle based gathering process.
func (a *Agent) GatherCandidates() error {
	var gatherErr error

	if runErr := a.run(a.context(), func(ctx context.Context, agent *Agent) {
		if a.gatheringState != GatheringStateNew {
			gatherErr = ErrMultipleGatherAttempted
			return
		} else if a.onCandidateHdlr.Load() == nil {
			gatherErr = ErrNoOnCandidateHandler
			return
		}

		a.gatherCandidateCancel() // Cancel previous gathering routine
		ctx, cancel := context.WithCancel(ctx)
		a.gatherCandidateCancel = cancel
		a.gatherCandidateDone = make(chan struct{})

		go a.gatherCandidates(ctx)
	}); runErr != nil {
		return runErr
	}
	return gatherErr
}

func (a *Agent) gatherCandidates(ctx context.Context) {
	defer close(a.gatherCandidateDone)
	if err := a.setGatheringState(GatheringStateGathering); err != nil { //nolint:contextcheck
		a.log.Warnf("failed to set gatheringState to GatheringStateGathering: %v", err)
		return
	}

	var wg sync.WaitGroup
	for _, t := range a.candidateTypes {
		switch t {
		case CandidateTypeHost:
			wg.Add(1)
			go func() {
				a.gatherCandidatesLocal(ctx, a.networkTypes)
				wg.Done()
			}()
		case CandidateTypeServerReflexive:
			wg.Add(1)
			go func() {
				if a.udpMuxSrflx != nil {
					a.gatherCandidatesSrflxUDPMux(ctx, a.urls, a.networkTypes)
				} else {
					a.gatherCandidatesSrflx(ctx, a.urls, a.networkTypes)
				}
				wg.Done()
			}()
			if a.extIPMapper != nil && a.extIPMapper.candidateType == CandidateTypeServerReflexive {
				wg.Add(1)
				go func() {
					a.gatherCandidatesSrflxMapped(ctx, a.networkTypes)
					wg.Done()
				}()
			}
		case CandidateTypeRelay:
			wg.Add(1)
			go func() {
				a.gatherCandidatesRelay(ctx, a.urls)
				wg.Done()
			}()
		case CandidateTypePeerReflexive, CandidateTypeUnspecified:
		}
	}

	// Block until all STUN and TURN URLs have been gathered (or timed out)
	wg.Wait()

	if err := a.setGatheringState(GatheringStateComplete); err != nil { //nolint:contextcheck
		a.log.Warnf("failed to set gatheringState to GatheringStateComplete: %v", err)
	}
}

func (a *Agent) gatherCandidatesLocal(ctx context.Context, networkTypes []NetworkType) { //nolint:gocognit
	networks := map[string]struct{}{}
	for _, networkType := range networkTypes {
		if networkType.IsTCP() {
			networks[tcp] = struct{}{}
		} else {
			networks[udp] = struct{}{}
		}
	}

	// when UDPMux is enabled, skip other UDP candidates
	if a.udpMux != nil {
		if err := a.gatherCandidatesLocalUDPMux(ctx); err != nil {
			a.log.Warnf("could not create host candidate for UDPMux: %s", err)
		}
		delete(networks, udp)
	}

	localIPs, err := localInterfaces(a.net, a.interfaceFilter, a.ipFilter, networkTypes, a.includeLoopback)
	if err != nil {
		a.log.Warnf("failed to iterate local interfaces, host candidates will not be gathered %s", err)
		return
	}

	for _, ip := range localIPs {
		mappedIP := ip
		if a.mDNSMode != MulticastDNSModeQueryAndGather && a.extIPMapper != nil && a.extIPMapper.candidateType == CandidateTypeHost {
			if _mappedIP, innerErr := a.extIPMapper.findExternalIP(ip.String()); innerErr == nil {
				mappedIP = _mappedIP
			} else {
				a.log.Warnf("1:1 NAT mapping is enabled but no external IP is found for %s", ip.String())
			}
		}

		address := mappedIP.String()
		if a.mDNSMode == MulticastDNSModeQueryAndGather {
			address = a.mDNSName
		}

		for network := range networks {
			type connAndPort struct {
				conn net.PacketConn
				port int
			}
			var (
				conns   []connAndPort
				tcpType TCPType
			)

			switch network {
			case tcp:
				// Handle ICE TCP passive mode
				var muxConns []net.PacketConn
				if multi, ok := a.tcpMux.(AllConnsGetter); ok {
					a.log.Debugf("GetAllConns by ufrag: %s", a.localUfrag)
					muxConns, err = multi.GetAllConns(a.localUfrag, mappedIP.To4() == nil, ip)
					if err != nil {
						if !errors.Is(err, ErrTCPMuxNotInitialized) {
							a.log.Warnf("error getting all tcp conns by ufrag: %s %s %s", network, ip, a.localUfrag)
						}
						continue
					}
				} else {
					a.log.Debugf("GetConn by ufrag: %s", a.localUfrag)
					conn, err := a.tcpMux.GetConnByUfrag(a.localUfrag, mappedIP.To4() == nil, ip)
					if err != nil {
						if !errors.Is(err, ErrTCPMuxNotInitialized) {
							a.log.Warnf("error getting tcp conn by ufrag: %s %s %s", network, ip, a.localUfrag)
						}
						continue
					}
					muxConns = []net.PacketConn{conn}
				}

				// Extract the port for each PacketConn we got.
				for _, conn := range muxConns {
					if tcpConn, ok := conn.LocalAddr().(*net.TCPAddr); ok {
						conns = append(conns, connAndPort{conn, tcpConn.Port})
					} else {
						a.log.Warnf("failed to get port of conn from TCPMux: %s %s %s", network, ip, a.localUfrag)
					}
				}
				if len(conns) == 0 {
					// Didn't succeed with any, try the next network.
					continue
				}
				tcpType = TCPTypePassive
				// is there a way to verify that the listen address is even
				// accessible from the current interface.
			case udp:
				conn, err := listenUDPInPortRange(a.net, a.log, int(a.portMax), int(a.portMin), network, &net.UDPAddr{IP: ip, Port: 0})
				if err != nil {
					a.log.Warnf("could not listen %s %s", network, ip)
					continue
				}

				if udpConn, ok := conn.LocalAddr().(*net.UDPAddr); ok {
					conns = append(conns, connAndPort{conn, udpConn.Port})
				} else {
					a.log.Warnf("failed to get port of UDPAddr from ListenUDPInPortRange: %s %s %s", network, ip, a.localUfrag)
					continue
				}
			}

			for _, connAndPort := range conns {
				hostConfig := CandidateHostConfig{
					Network:   network,
					Address:   address,
					Port:      connAndPort.port,
					Component: ComponentRTP,
					TCPType:   tcpType,
				}

				c, err := NewCandidateHost(&hostConfig)
				if err != nil {
					closeConnAndLog(connAndPort.conn, a.log, fmt.Sprintf("Failed to create host candidate: %s %s %d: %v", network, mappedIP, connAndPort.port, err))
					continue
				}

				if a.mDNSMode == MulticastDNSModeQueryAndGather {
					if err = c.setIP(ip); err != nil {
						closeConnAndLog(connAndPort.conn, a.log, fmt.Sprintf("Failed to create host candidate: %s %s %d: %v", network, mappedIP, connAndPort.port, err))
						continue
					}
				}

				if err := a.addCandidate(ctx, c, connAndPort.conn); err != nil {
					if closeErr := c.close(); closeErr != nil {
						a.log.Warnf("Failed to close candidate: %v", closeErr)
					}
					a.log.Warnf("Failed to append to localCandidates and run onCandidateHdlr: %v", err)
				}
			}
		}
	}
}

func (a *Agent) gatherCandidatesLocalUDPMux(ctx context.Context) error { //nolint:gocognit
	if a.udpMux == nil {
		return errUDPMuxDisabled
	}

	localAddresses := a.udpMux.GetListenAddresses()

	for _, addr := range localAddresses {
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			return errInvalidAddress
		}
		candidateIP := udpAddr.IP
		if a.extIPMapper != nil && a.extIPMapper.candidateType == CandidateTypeHost {
			if mappedIP, innerErr := a.extIPMapper.findExternalIP(candidateIP.String()); innerErr != nil {
				a.log.Warnf("1:1 NAT mapping is enabled but no external IP is found for %s", candidateIP.String())
				continue
			} else {
				candidateIP = mappedIP
			}
		}

		conn, err := a.udpMux.GetConn(a.localUfrag, udpAddr)
		if err != nil {
			return err
		}
		hostConfig := CandidateHostConfig{
			Network:   udp,
			Address:   candidateIP.String(),
			Port:      udpAddr.Port,
			Component: ComponentRTP,
		}

		c, err := NewCandidateHost(&hostConfig)
		if err != nil {
			closeConnAndLog(conn, a.log, fmt.Sprintf("Failed to create host mux candidate: %s %d: %v", candidateIP, udpAddr.Port, err))
			continue
		}

		if err := a.addCandidate(ctx, c, conn); err != nil {
			if closeErr := c.close(); closeErr != nil {
				a.log.Warnf("Failed to close candidate: %v", closeErr)
			}

			closeConnAndLog(conn, a.log, fmt.Sprintf("Failed to add candidate: %s %d: %v", candidateIP, udpAddr.Port, err))
			continue
		}
	}

	return nil
}

func (a *Agent) gatherCandidatesSrflxMapped(ctx context.Context, networkTypes []NetworkType) {
	var wg sync.WaitGroup
	defer wg.Wait()

	for _, networkType := range networkTypes {
		if networkType.IsTCP() {
			continue
		}

		network := networkType.String()
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := listenUDPInPortRange(a.net, a.log, int(a.portMax), int(a.portMin), network, &net.UDPAddr{IP: nil, Port: 0})
			if err != nil {
				a.log.Warnf("Failed to listen %s: %v", network, err)
				return
			}

			lAddr, ok := conn.LocalAddr().(*net.UDPAddr)
			if !ok {
				closeConnAndLog(conn, a.log, "1:1 NAT mapping is enabled but LocalAddr is not a UDPAddr")
				return
			}

			mappedIP, err := a.extIPMapper.findExternalIP(lAddr.IP.String())
			if err != nil {
				closeConnAndLog(conn, a.log, fmt.Sprintf("1:1 NAT mapping is enabled but no external IP is found for %s", lAddr.IP.String()))
				return
			}

			srflxConfig := CandidateServerReflexiveConfig{
				Network:   network,
				Address:   mappedIP.String(),
				Port:      lAddr.Port,
				Component: ComponentRTP,
				RelAddr:   lAddr.IP.String(),
				RelPort:   lAddr.Port,
			}
			c, err := NewCandidateServerReflexive(&srflxConfig)
			if err != nil {
				closeConnAndLog(conn, a.log, fmt.Sprintf("Failed to create server reflexive candidate: %s %s %d: %v",
					network,
					mappedIP.String(),
					lAddr.Port,
					err))
				return
			}

			if err := a.addCandidate(ctx, c, conn); err != nil {
				if closeErr := c.close(); closeErr != nil {
					a.log.Warnf("Failed to close candidate: %v", closeErr)
				}
				a.log.Warnf("Failed to append to localCandidates and run onCandidateHdlr: %v", err)
			}
		}()
	}
}

func (a *Agent) gatherCandidatesSrflxUDPMux(ctx context.Context, urls []*URL, networkTypes []NetworkType) { //nolint:gocognit
	var wg sync.WaitGroup
	defer wg.Wait()

	for _, networkType := range networkTypes {
		if networkType.IsTCP() {
			continue
		}

		for i := range urls {
			for _, listenAddr := range a.udpMuxSrflx.GetListenAddresses() {
				udpAddr, ok := listenAddr.(*net.UDPAddr)
				if !ok {
					a.log.Warn("Failed to cast udpMuxSrflx listen address to UDPAddr")
					continue
				}
				wg.Add(1)
				go func(url URL, network string, localAddr *net.UDPAddr) {
					defer wg.Done()

					hostPort := fmt.Sprintf("%s:%d", url.Host, url.Port)
					serverAddr, err := a.net.ResolveUDPAddr(network, hostPort)
					if err != nil {
						a.log.Warnf("failed to resolve stun host: %s: %v", hostPort, err)
						return
					}

					xorAddr, err := a.udpMuxSrflx.GetXORMappedAddr(serverAddr, stunGatherTimeout)
					if err != nil {
						a.log.Warnf("could not get server reflexive address %s %s: %v", network, url, err)
						return
					}

					conn, err := a.udpMuxSrflx.GetConnForURL(a.localUfrag, url.String(), localAddr)
					if err != nil {
						a.log.Warnf("could not find connection in UDPMuxSrflx %s %s: %v", network, url, err)
						return
					}

					ip := xorAddr.IP
					port := xorAddr.Port

					srflxConfig := CandidateServerReflexiveConfig{
						Network:   network,
						Address:   ip.String(),
						Port:      port,
						Component: ComponentRTP,
						RelAddr:   localAddr.IP.String(),
						RelPort:   localAddr.Port,
					}
					c, err := NewCandidateServerReflexive(&srflxConfig)
					if err != nil {
						closeConnAndLog(conn, a.log, fmt.Sprintf("Failed to create server reflexive candidate: %s %s %d: %v", network, ip, port, err))
						return
					}

					if err := a.addCandidate(ctx, c, conn); err != nil {
						if closeErr := c.close(); closeErr != nil {
							a.log.Warnf("Failed to close candidate: %v", closeErr)
						}
						a.log.Warnf("Failed to append to localCandidates and run onCandidateHdlr: %v", err)
					}
				}(*urls[i], networkType.String(), udpAddr)
			}
		}
	}
}

func (a *Agent) gatherCandidatesSrflx(ctx context.Context, urls []*URL, networkTypes []NetworkType) { //nolint:gocognit
	var wg sync.WaitGroup
	defer wg.Wait()

	for _, networkType := range networkTypes {
		if networkType.IsTCP() {
			continue
		}

		for i := range urls {
			wg.Add(1)
			go func(url URL, network string) {
				defer wg.Done()

				hostPort := fmt.Sprintf("%s:%d", url.Host, url.Port)
				serverAddr, err := a.net.ResolveUDPAddr(network, hostPort)
				if err != nil {
					a.log.Warnf("failed to resolve stun host: %s: %v", hostPort, err)
					return
				}

				conn, err := listenUDPInPortRange(a.net, a.log, int(a.portMax), int(a.portMin), network, &net.UDPAddr{IP: nil, Port: 0})
				if err != nil {
					closeConnAndLog(conn, a.log, fmt.Sprintf("Failed to listen for %s: %v", serverAddr.String(), err))
					return
				}
				// If the agent closes midway through the connection
				// we end it early to prevent close delay.
				cancelCtx, cancelFunc := context.WithCancel(ctx)
				defer cancelFunc()
				go func() {
					select {
					case <-cancelCtx.Done():
						return
					case <-a.done:
						_ = conn.Close()
					}
				}()

				xorAddr, err := getXORMappedAddr(conn, serverAddr, stunGatherTimeout)
				if err != nil {
					closeConnAndLog(conn, a.log, fmt.Sprintf("could not get server reflexive address %s %s: %v", network, url, err))
					return
				}

				ip := xorAddr.IP
				port := xorAddr.Port

				lAddr := conn.LocalAddr().(*net.UDPAddr) //nolint:forcetypeassert
				srflxConfig := CandidateServerReflexiveConfig{
					Network:   network,
					Address:   ip.String(),
					Port:      port,
					Component: ComponentRTP,
					RelAddr:   lAddr.IP.String(),
					RelPort:   lAddr.Port,
				}
				c, err := NewCandidateServerReflexive(&srflxConfig)
				if err != nil {
					closeConnAndLog(conn, a.log, fmt.Sprintf("Failed to create server reflexive candidate: %s %s %d: %v", network, ip, port, err))
					return
				}

				if err := a.addCandidate(ctx, c, conn); err != nil {
					if closeErr := c.close(); closeErr != nil {
						a.log.Warnf("Failed to close candidate: %v", closeErr)
					}
					a.log.Warnf("Failed to append to localCandidates and run onCandidateHdlr: %v", err)
				}
			}(*urls[i], networkType.String())
		}
	}
}

func (a *Agent) gatherCandidatesRelay(ctx context.Context, urls []*URL) { //nolint:gocognit
	var wg sync.WaitGroup
	defer wg.Wait()

	network := NetworkTypeUDP4.String()
	for i := range urls {
		switch {
		case urls[i].Scheme != SchemeTypeTURN && urls[i].Scheme != SchemeTypeTURNS:
			continue
		case urls[i].Username == "":
			a.log.Errorf("Failed to gather relay candidates: %v", ErrUsernameEmpty)
			return
		case urls[i].Password == "":
			a.log.Errorf("Failed to gather relay candidates: %v", ErrPasswordEmpty)
			return
		}

		wg.Add(1)
		go func(url URL) {
			defer wg.Done()
			TURNServerAddr := fmt.Sprintf("%s:%d", url.Host, url.Port)
			var (
				locConn       net.PacketConn
				err           error
				RelAddr       string
				RelPort       int
				relayProtocol string
			)

			switch {
			case url.Proto == ProtoTypeUDP && url.Scheme == SchemeTypeTURN:
				if locConn, err = a.net.ListenPacket(network, "0.0.0.0:0"); err != nil {
					a.log.Warnf("Failed to listen %s: %v", network, err)
					return
				}

				RelAddr = locConn.LocalAddr().(*net.UDPAddr).IP.String() //nolint:forcetypeassert
				RelPort = locConn.LocalAddr().(*net.UDPAddr).Port        //nolint:forcetypeassert
				relayProtocol = udp
			case a.proxyDialer != nil && url.Proto == ProtoTypeTCP &&
				(url.Scheme == SchemeTypeTURN || url.Scheme == SchemeTypeTURNS):
				conn, connectErr := a.proxyDialer.Dial(NetworkTypeTCP4.String(), TURNServerAddr)
				if connectErr != nil {
					a.log.Warnf("Failed to Dial TCP Addr %s via proxy dialer: %v", TURNServerAddr, connectErr)
					return
				}

				RelAddr = conn.LocalAddr().(*net.TCPAddr).IP.String() //nolint:forcetypeassert
				RelPort = conn.LocalAddr().(*net.TCPAddr).Port        //nolint:forcetypeassert
				if url.Scheme == SchemeTypeTURN {
					relayProtocol = tcp
				} else if url.Scheme == SchemeTypeTURNS {
					relayProtocol = "tls"
				}
				locConn = turn.NewSTUNConn(conn)

			case url.Proto == ProtoTypeTCP && url.Scheme == SchemeTypeTURN:
				tcpAddr, connectErr := net.ResolveTCPAddr(NetworkTypeTCP4.String(), TURNServerAddr)
				if connectErr != nil {
					a.log.Warnf("Failed to resolve TCP Addr %s: %v", TURNServerAddr, connectErr)
					return
				}

				conn, connectErr := net.DialTCP(NetworkTypeTCP4.String(), nil, tcpAddr)
				if connectErr != nil {
					a.log.Warnf("Failed to Dial TCP Addr %s: %v", TURNServerAddr, connectErr)
					return
				}

				RelAddr = conn.LocalAddr().(*net.TCPAddr).IP.String() //nolint:forcetypeassert
				RelPort = conn.LocalAddr().(*net.TCPAddr).Port        //nolint:forcetypeassert
				relayProtocol = tcp
				locConn = turn.NewSTUNConn(conn)
			case url.Proto == ProtoTypeUDP && url.Scheme == SchemeTypeTURNS:
				udpAddr, connectErr := net.ResolveUDPAddr(network, TURNServerAddr)
				if connectErr != nil {
					a.log.Warnf("Failed to resolve UDP Addr %s: %v", TURNServerAddr, connectErr)
					return
				}

				conn, connectErr := dtls.Dial(network, udpAddr, &dtls.Config{ //nolint:contextcheck
					ServerName:         url.Host,
					InsecureSkipVerify: a.insecureSkipVerify, //nolint:gosec
				})
				if connectErr != nil {
					a.log.Warnf("Failed to Dial DTLS Addr %s: %v", TURNServerAddr, connectErr)
					return
				}

				RelAddr = conn.LocalAddr().(*net.UDPAddr).IP.String() //nolint:forcetypeassert
				RelPort = conn.LocalAddr().(*net.UDPAddr).Port        //nolint:forcetypeassert
				relayProtocol = "dtls"
				locConn = &fakePacketConn{conn}
			case url.Proto == ProtoTypeTCP && url.Scheme == SchemeTypeTURNS:
				conn, connectErr := tls.Dial(NetworkTypeTCP4.String(), TURNServerAddr, &tls.Config{
					InsecureSkipVerify: a.insecureSkipVerify, //nolint:gosec
				})
				if connectErr != nil {
					a.log.Warnf("Failed to Dial TLS Addr %s: %v", TURNServerAddr, connectErr)
					return
				}
				RelAddr = conn.LocalAddr().(*net.TCPAddr).IP.String() //nolint:forcetypeassert
				RelPort = conn.LocalAddr().(*net.TCPAddr).Port        //nolint:forcetypeassert
				relayProtocol = "tls"
				locConn = turn.NewSTUNConn(conn)
			default:
				a.log.Warnf("Unable to handle URL in gatherCandidatesRelay %v", url)
				return
			}

			client, err := turn.NewClient(&turn.ClientConfig{
				TURNServerAddr: TURNServerAddr,
				Conn:           locConn,
				Username:       url.Username,
				Password:       url.Password,
				LoggerFactory:  a.loggerFactory,
				Net:            a.net,
			})
			if err != nil {
				closeConnAndLog(locConn, a.log, fmt.Sprintf("Failed to build new turn.Client %s %s", TURNServerAddr, err))
				return
			}

			if err = client.Listen(); err != nil {
				client.Close()
				closeConnAndLog(locConn, a.log, fmt.Sprintf("Failed to listen on turn.Client %s %s", TURNServerAddr, err))
				return
			}

			relayConn, err := client.Allocate()
			if err != nil {
				client.Close()
				closeConnAndLog(locConn, a.log, fmt.Sprintf("Failed to allocate on turn.Client %s %s", TURNServerAddr, err))
				return
			}

			rAddr := relayConn.LocalAddr().(*net.UDPAddr) //nolint:forcetypeassert
			relayConfig := CandidateRelayConfig{
				Network:       network,
				Component:     ComponentRTP,
				Address:       rAddr.IP.String(),
				Port:          rAddr.Port,
				RelAddr:       RelAddr,
				RelPort:       RelPort,
				RelayProtocol: relayProtocol,
				OnClose: func() error {
					client.Close()
					return locConn.Close()
				},
			}
			relayConnClose := func() {
				if relayConErr := relayConn.Close(); relayConErr != nil {
					a.log.Warnf("Failed to close relay %v", relayConErr)
				}
			}
			candidate, err := NewCandidateRelay(&relayConfig)
			if err != nil {
				relayConnClose()

				client.Close()
				closeConnAndLog(locConn, a.log, fmt.Sprintf("Failed to create relay candidate: %s %s: %v", network, rAddr.String(), err))
				return
			}

			if err := a.addCandidate(ctx, candidate, relayConn); err != nil {
				relayConnClose()

				if closeErr := candidate.close(); closeErr != nil {
					a.log.Warnf("Failed to close candidate: %v", closeErr)
				}
				a.log.Warnf("Failed to append to localCandidates and run onCandidateHdlr: %v", err)
			}
		}(*urls[i])
	}
}
