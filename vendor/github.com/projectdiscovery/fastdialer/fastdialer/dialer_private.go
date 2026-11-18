package fastdialer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	"github.com/projectdiscovery/fastdialer/fastdialer/utils"
	retryabledns "github.com/projectdiscovery/retryabledns"
	cryptoutil "github.com/projectdiscovery/utils/crypto"
	"github.com/projectdiscovery/utils/errkit"
	iputil "github.com/projectdiscovery/utils/ip"
	ptrutil "github.com/projectdiscovery/utils/ptr"
	utls "github.com/refraction-networking/utls"
	ztls "github.com/zmap/zcrypto/tls"
	"golang.org/x/net/proxy"
)

// this l4dialer interface is used to conditionally pass net.Dialer or its wrapper
type l4dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

var _ l4dialer = &utils.DialWrap{}

type proxyL4Dialer struct {
	dialer  proxy.Dialer
	timeout time.Duration
}

var _ l4dialer = &proxyL4Dialer{}

func (p *proxyL4Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if cd, ok := p.dialer.(proxy.ContextDialer); ok {
		if p.timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, p.timeout)
			defer cancel()
		}
		return cd.DialContext(ctx, network, address)
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}
	// results is unbuffered so a conn that arrives after we gave up is seen by
	// the dialing goroutine, which closes it instead of leaking it
	results := make(chan dialResult)
	abandoned := make(chan struct{})
	defer close(abandoned)
	go func() {
		conn, err := p.dialer.Dial(network, address)
		select {
		case results <- dialResult{conn, err}:
		case <-abandoned:
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()

	timeout := p.timeout
	if deadline, ok := ctx.Deadline(); ok {
		ctxTimeout := time.Until(deadline)
		if timeout == 0 || (ctxTimeout > 0 && ctxTimeout < timeout) {
			timeout = ctxTimeout
		}
	}

	var timer *time.Timer
	if timeout > 0 {
		timer = time.NewTimer(timeout)
		defer timer.Stop()
	}

	var timerCh <-chan time.Time
	if timer != nil {
		timerCh = timer.C
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timerCh:
		return nil, fmt.Errorf("timeout after %v", timeout)
	case res := <-results:
		return res.conn, res.err
	}
}

type dialOptions struct {
	network             string
	address             string
	shouldUseTLS        bool
	shouldUseZTLS       bool
	tlsconfig           *tls.Config
	ztlsconfig          *ztls.Config
	impersonateStrategy impersonate.Strategy
	impersonateIdentity *impersonate.Identity

	// internally used in dialer_private
	ips      []string
	port     string
	hostname string
	fixedIP  string
}

// connHash returns a hash of the connection. The pinned ip is part of it, so
// dials of one address pinned to different ips never share a cached dialer.
func (d *dialOptions) connHash() string {
	if d.fixedIP != "" {
		return fmt.Sprintf("%s-%s-%s", d.network, d.address, d.fixedIP)
	}
	return fmt.Sprintf("%s-%s", d.network, d.address)
}

// parseAddress splits the address into hostname and port and picks the ip the
// dial is pinned to, if any.
func (d *dialOptions) parseAddress(ctx context.Context) error {
	var hostname, port, fixedIP string
	if strings.HasPrefix(d.address, "[") {
		closeBracketIndex := strings.Index(d.address, "]")
		if closeBracketIndex == -1 {
			return MalformedIP6Error
		}
		hostname = d.address[1:closeBracketIndex]
		if len(d.address) < closeBracketIndex+2 {
			return NoPortSpecifiedError
		}
		port = d.address[closeBracketIndex+2:]
	} else {
		addressParts := strings.SplitN(d.address, ":", 3)
		if len(addressParts) < 2 {
			// no port => error
			return NoPortSpecifiedError
		}
		// ip|host:port
		hostname = addressParts[0]
		port = addressParts[1]
		// ip|host:port:ip => curl --resolve ip:port:ip
		var addressIP string
		if len(addressParts) > 2 {
			addressIP = addressParts[2]
		}
		fixedIP = pinnedIP(ctx, hostname, addressIP)
	}

	d.hostname = asAscii(hostname)
	d.port = port
	d.fixedIP = fixedIP
	return nil
}

// pinnedIP returns the ip a dial to hostname is pinned to, in order of
// precedence: the IP context option, the ip of a host:port:ip address and a
// resolve override.
func pinnedIP(ctx context.Context, hostname, addressIP string) string {
	if ctxIP := ctx.Value(IP); ctxIP != nil {
		return fmt.Sprint(ctxIP)
	}
	if addressIP != "" {
		return addressIP
	}
	return resolveOverride(ctx, hostname)
}

// logAddress returns the address to be logged in case of error
func (d *dialOptions) logAddress() string {
	logAddress := d.hostname
	if logAddress == "" {
		logAddress = d.ips[0]
	}
	return net.JoinHostPort(logAddress, d.port)
}

func (d *Dialer) dial(ctx context.Context, opts *dialOptions) (conn net.Conn, err error) {
	// add global timeout to context
	ctx, cancel := context.WithTimeoutCause(ctx, d.GetTimeout(), ErrDialTimeout)
	defer cancel()

	// the pinned ip is read before the cache lookup, as it is part of the key
	if err := opts.parseAddress(ctx); err != nil {
		return nil, err
	}
	hostname, port := opts.hostname, opts.port

	var IPS []string
	// check if this is present in cache
	dw, err := d.dialCache.GetIFPresent(opts.connHash())
	if err == nil && dw != nil {
		// OnValidateTarget may reject a target it allowed when it was cached
		for _, ip := range dw.IPs() {
			if !d.isValidTarget(hostname, ip.String(), port) {
				// the uncached path filters the ips again and reports the invalid ones
				dw = nil
				break
			}
		}
	}
	if err != nil || dw == nil {
		// hostname rules are regexes, which networkpolicy only applies to
		// hostnames, never to the resolved ips
		if hostname != "" && !iputil.IsIP(hostname) && !d.networkpolicy.Validate(hostname) {
			if d.options.OnInvalidTarget != nil {
				d.options.OnInvalidTarget(hostname, "", port)
			}
			return nil, NoAddressAllowedError
		}

		// use fixed ip as first
		if opts.fixedIP != "" {
			IPS = append(IPS, opts.fixedIP)
		} else {
			cacheData, err, _ := d.resolutionsGroup.Do(hostname, func() (interface{}, error) {
				return d.GetDNSData(hostname)
			})
			if cacheData == nil {
				return nil, ResolveHostError
			}
			data := cacheData.(*retryabledns.DNSData)
			if err != nil || len(data.A)+len(data.AAAA) == 0 {
				return nil, NoAddressFoundError
			}
			IPS = append(IPS, data.A...)
			IPS = append(IPS, data.AAAA...)
		}

		filteredIPs := []string{}

		// filter valid/invalid ips
		for _, ip := range IPS {
			if !d.isValidTarget(hostname, ip, port) {
				if d.options.OnInvalidTarget != nil {
					d.options.OnInvalidTarget(hostname, ip, port)
				}
				continue
			}
			if d.options.OnBeforeDial != nil {
				d.options.OnBeforeDial(hostname, ip, port)
			}
			// add it as allowed/filter ip
			filteredIPs = append(filteredIPs, ip)
		}

		if len(filteredIPs) == 0 {
			return nil, NoAddressAllowedError
		}

		// update allowed ips
		IPS = filteredIPs
		opts.ips = IPS
	}

	var finalDialer l4dialer = d.dialer
	if d.proxyDialer != nil {
		finalDialer = &proxyL4Dialer{dialer: *d.proxyDialer, timeout: d.options.DialerTimeout}
	}

	if dw == nil && hostname != "" && len(IPS) > 0 && d.proxyDialer == nil {
		// only cache it if below conditions are met
		// 1. it is already not present
		// 2. it is a domain and not ip
		// 3. it has at least 1 valid ip
		// 4. proxy dialer is not set
		dw, err = utils.NewDialWrap(d.dialer, IPS, opts.network, opts.address, opts.port)
		if err != nil {
			return nil, errkit.Wrap(err, "could not create dialwrap")
		}
		dw.SetExpireConnAfter(d.options.ConnectionCacheExpiry)
		if err = d.dialCache.Set(opts.connHash(), dw); err != nil {
			return nil, errkit.Wrap(err, "could not set dialwrap")
		}
	}
	if dw != nil {
		finalDialer = dw
		// when using dw ip , network , port etc are preset
		// so get any one of them to avoid breaking further logic
		ip, port := dw.Address()
		opts.ips = []string{ip}
		opts.port = port
	}

	conn, err = d.dialIPS(ctx, finalDialer, opts)
	if err == nil && conn == nil {
		err = CouldNotConnectError
	} else if err == nil && conn.RemoteAddr() == nil {
		err = errkit.New("remote address is nil")
		conn = nil
	}
	if d.options.OnDialResult != nil {
		d.options.OnDialResult(ctx, hostname, opts.port, err)
	}
	if err != nil {
		return
	}
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if d.options.WithDialerHistory && d.dialerHistory != nil {
		setErr := d.dialerHistory.Set(hostname, []byte(ip))
		if setErr != nil {
			return nil, setErr
		}
	}
	if d.options.OnDialCallback != nil {
		d.options.OnDialCallback(hostname, ip)
	}
	if d.options.WithTLSData && opts.shouldUseTLS {
		if connTLS, ok := conn.(*tls.Conn); ok {
			var data bytes.Buffer
			connState := connTLS.ConnectionState()
			err := json.NewEncoder(&data).Encode(cryptoutil.TLSGrab(&connState))
			if err != nil {
				return nil, err
			}
			setErr := d.dialerTLSData.Set(hostname, data.Bytes())
			if setErr != nil {
				return nil, setErr
			}
		}
	}
	return
}

func (d *Dialer) dialIPS(ctx context.Context, l4 l4dialer, opts *dialOptions) (conn net.Conn, err error) {
	hostPort := net.JoinHostPort(opts.ips[0], opts.port)

	if opts.shouldUseTLS {
		tlsconfigCopy := opts.tlsconfig.Clone()

		switch {
		case d.options.SNIName != "":
			tlsconfigCopy.ServerName = d.options.SNIName
		case ctx.Value(SniName) != nil:
			sniName := ctx.Value(SniName).(string)
			tlsconfigCopy.ServerName = sniName
		case !iputil.IsIP(opts.hostname):
			tlsconfigCopy.ServerName = opts.hostname
		}

		if opts.impersonateStrategy == impersonate.None {
			l4Conn, err := l4.DialContext(ctx, opts.network, hostPort)
			if err != nil {
				return nil, d.handleDialError(err, opts)
			}
			TlsConn := tls.Client(l4Conn, tlsconfigCopy)
			clearDeadline := d.setHandshakeDeadline(ctx, l4Conn)
			if err := TlsConn.HandshakeContext(ctx); err != nil {
				_ = TlsConn.Close()
				// some non-HTTP services reject the http/1.1 of DefaultTLSConfig,
				// while a caller's own protocols are theirs to keep
				if opts.tlsconfig == DefaultTLSConfig && rejectedALPN(err) {
					retry := *opts
					retry.tlsconfig = DefaultTLSConfig.Clone()
					retry.tlsconfig.NextProtos = nil
					return d.dialIPS(ctx, l4, &retry)
				}
				if d.canFallbackToZTLS(ctx, tlsconfigCopy, err) {
					ztlsconfigCopy, convErr := AsZTLSConfig(tlsconfigCopy)
					if convErr != nil {
						return nil, errkit.Wrap(convErr, "could not convert tls config to ztls config")
					}
					ztlsconfigCopy.CipherSuites = ztls.ChromeCiphers
					ztlsConn, ztlsErr := d.dialZTLS(ctx, l4, opts, hostPort, ztlsconfigCopy)
					if ztlsErr != nil {
						return nil, errkit.Join(errkit.Wrap(err, "could not tls handshake"), errkit.Wrap(ztlsErr, "ztls fallback failed"))
					}
					return ztlsConn, nil
				}
				return nil, errkit.Wrap(err, "could not tls handshake")
			}
			clearDeadline()
			conn = TlsConn
		} else {
			nativeConn, err := l4.DialContext(ctx, opts.network, hostPort)
			if err != nil {
				return nil, d.handleDialError(err, opts)
			}
			uTLSConn, err := d.handshakeImpersonated(ctx, nativeConn, tlsconfigCopy, opts)
			if err != nil {
				_ = nativeConn.Close()
				return nil, err
			}
			conn = uTLSConn
		}
	} else if opts.shouldUseZTLS {
		ztlsconfigCopy := opts.ztlsconfig.Clone()
		switch {
		case d.options.SNIName != "":
			ztlsconfigCopy.ServerName = d.options.SNIName
		case ctx.Value(SniName) != nil:
			sniName := ctx.Value(SniName).(string)
			ztlsconfigCopy.ServerName = sniName
		case !iputil.IsIP(opts.hostname):
			ztlsconfigCopy.ServerName = opts.hostname
		}
		return d.dialZTLS(ctx, l4, opts, hostPort, ztlsconfigCopy)
	} else {
		conn, err = l4.DialContext(ctx, opts.network, hostPort)
		err = d.handleDialError(err, opts)
	}
	return
}

// dialZTLS dials hostPort through l4 and runs a ztls client handshake with
// config. The connection is closed if the handshake fails.
func (d *Dialer) dialZTLS(ctx context.Context, l4 l4dialer, opts *dialOptions, hostPort string, config *ztls.Config) (net.Conn, error) {
	l4Conn, err := l4.DialContext(ctx, opts.network, hostPort)
	if err != nil {
		return nil, d.handleDialError(err, opts)
	}
	ztlsConn := ztls.Client(l4Conn, config)
	clearDeadline := d.setHandshakeDeadline(ctx, l4Conn)
	if err := ztlsConn.Handshake(); err != nil {
		_ = ztlsConn.Close()
		return nil, err
	}
	clearDeadline()
	return ztlsConn, nil
}

// handshakeImpersonated runs a utls client handshake over conn with config and
// the ClientHello of opts.impersonateStrategy. When it fails, closing conn is
// left to the caller that dialed it.
func (d *Dialer) handshakeImpersonated(ctx context.Context, conn net.Conn, config *tls.Config, opts *dialOptions) (*utls.UConn, error) {
	uTLSConfig := asUTLSConfig(config)
	var uTLSConn *utls.UConn
	switch opts.impersonateStrategy {
	case impersonate.Random:
		uTLSConn = utls.UClient(conn, uTLSConfig, randomClientHelloID())
	case impersonate.Custom:
		spec, ownSession := newClientHelloSpec(opts.impersonateIdentity)
		// utls panics when it loads a cached session into an
		// extension that already holds one
		if ownSession {
			uTLSConfig.ClientSessionCache = nil
		}
		uTLSConn = utls.UClient(conn, uTLSConfig, utls.HelloCustom)
		if err := uTLSConn.ApplyPreset(spec); err != nil {
			return nil, err
		}
	case impersonate.Chrome:
		uTLSConn = utls.UClient(conn, uTLSConfig, utls.HelloChrome_106_Shuffle)
	}
	if len(config.NextProtos) > 0 {
		if err := setALPN(uTLSConn, config.NextProtos); err != nil {
			return nil, err
		}
	}
	clearDeadline := d.setHandshakeDeadline(ctx, conn)
	if err := uTLSConn.Handshake(); err != nil {
		return nil, err
	}
	clearDeadline()
	return uTLSConn, nil
}

// canFallbackToZTLS reports whether a failed crypto/tls handshake (handshakeErr,
// made with config) may be retried once with ztls and ztls.ChromeCiphers, to
// reach servers that crypto/tls refuses to talk to (old versions, legacy
// ciphers). The fallback can be disabled with Options.DisableZtlsFallback or
// the DISABLE_ZTLS_FALLBACK environment variable.
//
// Only a handshake failure of a plain crypto/tls dial falls back; dial errors
// (including proxy errors), impersonated and ztls dials do not. The fallback is
// refused when a retry can't reach more servers: the context is done, the
// handshake timed out, the server doesn't speak TLS, or config requires TLS
// 1.3, which leaves no older version or cipher to retry with. It is also
// refused when config doesn't carry over to ztls, see [carriesOverToZTLS].
func (d *Dialer) canFallbackToZTLS(ctx context.Context, config *tls.Config, handshakeErr error) bool {
	if d.options.DisableZtlsFallback || disableZTLSFallback {
		return false
	}
	if ctx.Err() != nil || errkit.Is(handshakeErr, os.ErrDeadlineExceeded) {
		return false
	}
	var recordErr tls.RecordHeaderError
	if errkit.As(handshakeErr, &recordErr) || config.MinVersion >= tls.VersionTLS13 {
		return false
	}
	return carriesOverToZTLS(config)
}

// rejectedALPN reports whether the server ended the handshake with a
// no_application_protocol alert. crypto/tls doesn't export the type of
// received alerts, so the alert is matched by its text.
func rejectedALPN(err error) bool {
	var opErr *net.OpError
	return errkit.As(err, &opErr) && opErr.Op == "remote error" && opErr.Err != nil &&
		opErr.Err.Error() == "tls: no application protocol"
}

// carriesOverToZTLS reports whether a ztls retry with AsZTLSConfig(config)
// keeps the server checks, client certificate and ECH settings of config.
// AsZTLSConfig copies Certificates. It can't carry RootCAs, the verification
// callbacks, GetClientCertificate, or the ECH settings, so the retry would
// verify the server differently, omit a certificate chosen by callback, or
// send the hidden server name in the clear.
func carriesOverToZTLS(config *tls.Config) bool {
	return config.InsecureSkipVerify &&
		config.VerifyPeerCertificate == nil && config.VerifyConnection == nil &&
		config.GetClientCertificate == nil &&
		config.EncryptedClientHelloConfigList == nil && config.EncryptedClientHelloRejectionVerify == nil
}

// randomClientHelloID is HelloRandomized with the hybrid group tied to its key
// share. utls cannot answer a HelloRetryRequest for X25519MLKEM768, so a hello
// that advertises that group without a share fails when the server asks for it.
func randomClientHelloID() utls.ClientHelloID {
	weights := utls.DefaultWeights
	weights.CurveIDs_Append_X25519 = 1
	weights.KeyShare_Append_RandomGroups = 1
	id := utls.HelloRandomized
	id.Weights = &weights
	return id
}

// newClientHelloSpec returns the spec of identity for one connection, and
// whether the identity sets its own session.
//
// utls stores the state of a connection in the extensions of its spec: the
// server name, GREASE values and key shares it fills in, the padding it
// computes, and the session it resumes. Callers share an identity across dials
// and goroutines, so the spec gets a copy of each extension, and a new
// extension for the session that utls resumes. Otherwise concurrent dials
// would race on the identity, and a later dial would keep the server name of
// an earlier one, reuse key shares without their private keys, and fail or
// panic on a stored session.
//
// The spec keeps a server name or session ticket that the identity sets
// itself, and session extensions of other types, such as the
// FakePreSharedKeyExtension of ja3.ParseWithRaw. utls can't put a cached
// session in those.
func newClientHelloSpec(identity *impersonate.Identity) (spec *utls.ClientHelloSpec, ownSession bool) {
	s := utls.ClientHelloSpec(ptrutil.Safe(identity))
	s.Extensions = slices.Clone(s.Extensions)
	for i, ext := range s.Extensions {
		switch ext := ext.(type) {
		case *utls.SessionTicketExtension:
			if !ext.Initialized {
				s.Extensions[i] = &utls.SessionTicketExtension{}
				continue
			}
			ownSession = true
		case *utls.UtlsPreSharedKeyExtension:
			s.Extensions[i] = &utls.UtlsPreSharedKeyExtension{}
			continue
		case utls.ISessionTicketExtension, utls.PreSharedKeyExtension:
			ownSession = true
		}
		s.Extensions[i] = copyExtension(ext)
	}
	return &s, ownSession
}

// copyExtension returns a copy of ext that utls can fill in for one connection.
// utls assigns to the fields of an extension, and in place to the elements of
// some of its exported slices, such as the GREASE placeholders among the curves
// and versions, so the copy gets its own struct and exported slices. Any type
// is copied this way, since utls doesn't document which ones it writes to. An
// extension that isn't a pointer to a struct is returned as is.
func copyExtension(ext utls.TLSExtension) utls.TLSExtension {
	v := reflect.ValueOf(ext)
	if v.Kind() != reflect.Pointer || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		return ext
	}
	c := reflect.New(v.Elem().Type()).Elem()
	c.Set(v.Elem())
	for i := range c.NumField() {
		if f := c.Field(i); f.Kind() == reflect.Slice && f.CanSet() && !f.IsNil() {
			f.Set(reflect.AppendSlice(reflect.MakeSlice(f.Type(), 0, f.Len()), f))
		}
	}
	return c.Addr().Interface().(utls.TLSExtension)
}

// setALPN makes conn advertise protos as its ALPN protocols.
//
// Parroted and custom ClientHello specs carry their own ALPN extension, which
// overrides Config.NextProtos, so setALPN replaces that extension. A spec
// without ALPN stays without it, keeping its extension set.
func setALPN(conn *utls.UConn, protos []string) error {
	if err := conn.BuildHandshakeState(); err != nil {
		return err
	}
	for i, ext := range conn.Extensions {
		if _, ok := ext.(*utls.ALPNExtension); ok {
			conn.Extensions[i] = &utls.ALPNExtension{AlpnProtocols: protos}
		}
	}
	return nil
}

// handleDialError is a helper function to handle dial errors
// it also adds address attribute to the error
func (d *Dialer) handleDialError(err error, opts *dialOptions) error {
	if err == nil {
		return nil
	}
	errx := errkit.FromError(err)
	errx = errx.SetAttr(slog.Any("address", opts.logAddress())) //nolint (ref https://github.com/projectdiscovery/utils/issues/657)

	if errx.Kind() == errkit.ErrKindUnknown {
		if errx.Cause() != nil && strings.Contains(errx.Cause().Error(), "i/o timeout") {
			// mark timeout errors as temporary
			errx = errx.SetKind(errkit.ErrKindNetworkTemporary)

			if d.dialTimeoutErrors != nil {
				count, err := d.dialTimeoutErrors.GetIFPresent(opts.connHash())
				if err != nil {
					count = &atomic.Uint32{}
					count.Store(1)
				} else {
					count.Add(1)
				}
				_ = d.dialTimeoutErrors.Set(opts.connHash(), count)

				// update them to permanent if they happened multiple times within 30s
				if count.Load() > uint32(d.options.MaxTemporaryErrors) {
					errx = errx.ResetKind().SetKind(errkit.ErrKindNetworkPermanent)
				}
			}
		}
	}
	return errx
}

// setHandshakeDeadline bounds a TLS handshake by setting an absolute deadline on
// the underlying connection, derived from the dialer timeout and any earlier
// deadline already carried by ctx. It returns a function that clears the deadline
// once the handshake succeeds. Using the connection deadline avoids spawning a
// watchdog goroutine per handshake.
func (d *Dialer) setHandshakeDeadline(ctx context.Context, conn net.Conn) func() {
	deadline := time.Now().Add(d.GetTimeout())
	if cd, ok := ctx.Deadline(); ok && cd.Before(deadline) {
		deadline = cd
	}
	_ = conn.SetDeadline(deadline)
	return func() { _ = conn.SetDeadline(time.Time{}) }
}

// isValidTarget reports whether the network policy, the port lists and
// OnValidateTarget allow dialing ip.
func (d *Dialer) isValidTarget(hostname, ip, port string) bool {
	portInt, _ := strconv.Atoi(port)
	// Options.NetworkPolicy doesn't carry the port lists of Options, so both are checked
	if !d.networkpolicy.Validate(ip) || !d.networkpolicy.ValidatePort(portInt) || !d.validatePort(portInt) {
		return false
	}
	return d.options.OnValidateTarget == nil || d.options.OnValidateTarget(hostname, ip, port) == nil
}

func (d *Dialer) validatePort(port int) bool {
	for _, p := range d.options.DenyPortList {
		if p == port {
			return false
		}
	}
	if len(d.options.AllowPortList) > 0 {
		for _, p := range d.options.AllowPortList {
			if p == port {
				return true
			}
		}
		return false
	}
	return true
}
