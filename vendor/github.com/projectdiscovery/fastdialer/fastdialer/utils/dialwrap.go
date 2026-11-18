package utils

import (
	"context"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/utils/errkit"
	iputil "github.com/projectdiscovery/utils/ip"
)

// == DialWrap =====
// DialWrap is a net dialer wrapper optimized for dialing hostnames with multiple IPs.
// It attempts the first dial in parallel, blocking all other dials until this first dial is complete.
// If multiple connections are established during this first parallel dial, they are randomly distributed to
// all paused dials. If the first dial was successful or failed due to temporary reason like context cancellation,
// new connections are created as needed. if it was a permanent error like port being filtered new connections
// are not created and that permanent error is returned.
//
// when dialing new connections after first dial, a happy eyeballs algorithm is used to establish new connections
// Happy Eyeballs Algo =
// Ips are split into Ipv4 and Ipv6
// Ipv6 are first dialed in serial and after fallback delay (300ms) Ipv4 are dialed in parallel
// whichever returns first is used while the other is cancelled
// stdlib dialer uses the same approach
//
// Note:
// Earlier we had tried to reuse connections by always dialing in parallel,
// but that resulted in `use of closed network connection` error. which happens
// when tcp keep alive is disabled / not supported or the connection was used when it was expired(keep alive timeout)
// i.e why we have fallen back to use happy eyeballs algorithm.

// Error constants
var (
	// errGotConnection has already been established
	ErrInflightCancel       = errkit.New("context cancelled before establishing connection")
	ErrNoIPs                = errkit.New("no ips provided in dialWrap")
	ErrPortClosedOrFiltered = errkit.New("port closed or filtered").SetKind(errkit.ErrKindNetworkPermanent)

	// ExpireConnAfter is the default duration after which a cached connection
	// expires.
	//
	// Deprecated: use [DefaultConnExpiry] instead.
	ExpireConnAfter = time.Duration(5) * time.Second
)

const (
	// DefaultConnExpiry is the default duration after which a cached
	// connection expires.
	//
	// This is used when Options.ConnectionCacheExpiry is not set.
	// Use the SetExpireConnAfter method to adjust.
	DefaultConnExpiry = time.Duration(10) * time.Second
)

// dialResult represents the result of a dial operation
type dialResult struct {
	net.Conn
	error
	primary bool
	done    bool
	expiry  time.Time
}

// DialWrap wraps the net dialer taking in and only dials
// to given ips. This implementation retains the original
// Happy Eyeballs algorithm and dual stack support.
type DialWrap struct {
	dialer  *net.Dialer
	ipv4    []net.IP
	ipv6    []net.IP
	ips     []net.IP
	network string
	address string
	port    string

	// expireConnAfter is the duration after which a cached connection expires.
	expireConnAfter time.Duration

	// all connections blocks until a first connection is established
	// subsequent calls will behave upon first result
	busyFirstConnection      *atomic.Bool
	completedFirstConnection *atomic.Bool
	firstConnectionDuration  time.Duration
	mu                       sync.RWMutex
	// error returned by first connection
	err error

	firstConnCond *sync.Cond
}

// NewDialWrap creates a new dial wrap instance and returns it.
func NewDialWrap(dialer *net.Dialer, ips []string, network, address, port string) (*DialWrap, error) {
	var ipv4, valid, ipv6 []net.IP
	for _, ip := range ips {
		if iputil.IsIP(ip) {
			valid = append(valid, net.ParseIP(ip))
			if iputil.IsIPv4(ip) {
				ipv4 = append(ipv4, net.ParseIP(ip))
			} else {
				ipv6 = append(ipv6, net.ParseIP(ip))
			}
		}
	}
	if len(valid) == 0 {
		return nil, ErrNoIPs
	}
	return &DialWrap{
		dialer:                   dialer,
		ipv4:                     ipv4,
		ipv6:                     ipv6,
		ips:                      valid,
		expireConnAfter:          DefaultConnExpiry,
		completedFirstConnection: &atomic.Bool{},
		busyFirstConnection:      &atomic.Bool{},
		network:                  network,
		address:                  address,
		port:                     port,
		firstConnCond:            sync.NewCond(&sync.Mutex{}),
	}, nil
}

// DialContext is the main entry point for dialing
func (d *DialWrap) DialContext(ctx context.Context, _ string, _ string) (net.Conn, error) {
	// The caller that starts the first connection waits for it alone. Its
	// completion is signalled before the connection is handed over, so also
	// waiting on that signal could dial again and leak the first connection.
	if first := d.doFirstConnection(ctx); first != nil {
		select {
		case res, ok := <-first:
			if !ok {
				// closed channel so depending on the error
				// either dial new or return the error
				if d.err == nil {
					return d.dial(ctx)
				}
				return nil, d.err
			}
			if res.Conn != nil {
				// check expiry
				if res.expiry.Before(time.Now()) {
					_ = res.Close()
					return d.dial(ctx)
				}
				return res.Conn, nil
			}
			if d.err != nil {
				return nil, d.err
			}
			return nil, res.error
		case <-ctx.Done():
			go closeDialResults(first)
			return nil, errkit.Append(ErrInflightCancel, ctx.Err())
		}
	}
	select {
	case <-d.hasCompletedFirstConnection(ctx):
		// if first connection completed and it failed due to other reasons
		// and not due to context cancellation
		d.firstConnCond.L.Lock()
		err := d.err
		d.firstConnCond.L.Unlock()

		if err != nil && !errkit.Is(err, ErrInflightCancel) && !errkit.Is(err, context.Canceled) {
			return nil, err
		}
		return d.dial(ctx)
	case <-ctx.Done():
		return nil, errkit.Append(ErrInflightCancel, ctx.Err())
	}
}

// closeDialResults closes connections delivered after their caller gave up.
func closeDialResults(results <-chan *dialResult) {
	for res := range results {
		if res.Conn != nil {
			_ = res.Close()
		}
	}
}

func (d *DialWrap) doFirstConnection(ctx context.Context) chan *dialResult {
	if d.busyFirstConnection.Load() {
		return nil
	}
	d.busyFirstConnection.Store(true)
	now := time.Now()

	size := len(d.ipv4) + len(d.ipv6)
	ch := make(chan *dialResult, size)

	// dial parallel
	go func() {
		defer close(ch)

		conns, err := d.dialAllParallel(ctx)

		d.firstConnCond.L.Lock()
		d.SetFirstConnectionDuration(time.Since(now))
		d.completedFirstConnection.Store(true)
		d.firstConnCond.Broadcast()
		d.err = err
		d.firstConnCond.L.Unlock()

		if err != nil {
			ch <- &dialResult{error: err}
			return
		}
		for _, conn := range conns {
			ch <- conn
		}
	}()
	return ch
}

func (d *DialWrap) hasCompletedFirstConnection(ctx context.Context) chan struct{} {
	ch := make(chan struct{}, 1)

	go func() {
		defer close(ch)

		// Check immediately first
		if d.completedFirstConnection.Load() {
			return
		}

		d.firstConnCond.L.Lock()
		defer d.firstConnCond.L.Unlock()

		for !d.completedFirstConnection.Load() {
			if ctx.Err() != nil {
				return
			}
			d.firstConnCond.Wait()
		}
	}()
	return ch
}

// dialAllParallel connects to all the given addresses in parallel, returning
// immediately when the first successful connection is established.
// Remaining dial attempts are canceled to avoid unnecessary delays.
func (d *DialWrap) dialAllParallel(ctx context.Context) ([]*dialResult, error) {
	// check / adjust deadline
	deadline := d.deadline(ctx, time.Now())
	if !deadline.IsZero() {
		if d, ok := ctx.Deadline(); !ok || deadline.Before(d) {
			subCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			ctx = subCtx
		}
	}

	dialCtx, dialCancel := context.WithCancel(ctx)
	defer dialCancel()

	numIPs := len(d.ipv4) + len(d.ipv6)
	rec := make(chan *dialResult, numIPs)

	for _, ip := range d.ips {
		go func(ipx net.IP) {
			select {
			case <-dialCtx.Done():
				rec <- &dialResult{error: errkit.Append(ErrInflightCancel, dialCtx.Err())}
			default:
				c, err := d.dialer.DialContext(dialCtx, d.network, net.JoinHostPort(ipx.String(), d.port))
				rec <- &dialResult{Conn: c, error: err, expiry: time.Now().Add(d.expireConnAfter)}
			}
		}(ip)
	}

	var conns []*dialResult
	var errs []*dialResult
	received := 0

	for received < numIPs {
		select {
		case result := <-rec:
			received++
			if result.Conn != nil {
				conns = append(conns, result)

				dialCancel()
				go func() {
					for i := received; i < numIPs; i++ {
						if r := <-rec; r.Conn != nil {
							_ = r.Close()
						}
					}
				}()

				return conns, nil
			} else {
				if !errkit.Is(result.error, ErrInflightCancel) && !errkit.Is(result.error, context.Canceled) {
					errs = append(errs, result)
				}
			}
		case <-ctx.Done():
			return nil, errkit.Append(ErrInflightCancel, ctx.Err())
		}
	}

	if len(errs) == 0 {
		return nil, ErrInflightCancel
	}

	var finalErr error
	for _, v := range errs {
		finalErr = errkit.Append(finalErr, v.error)
	}

	// If not inflight cancel then it is a permanent error (port closed/filtered)
	if !errkit.Is(finalErr, ErrInflightCancel) {
		return nil, errkit.Append(ErrPortClosedOrFiltered, finalErr)
	}

	return nil, finalErr
}

// dial is the main dialing function
func (d *DialWrap) dial(ctx context.Context) (net.Conn, error) {
	deadline := d.deadline(ctx, time.Now())
	if !deadline.IsZero() {
		if d, ok := ctx.Deadline(); !ok || deadline.Before(d) {
			subCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			ctx = subCtx
		}
	}

	if d.network == "tcp" && d.dualStack() {
		return d.dialParallel(ctx, d.ipv4, d.ipv6, d.network, d.port)
	}
	return d.dialParallel(ctx, d.ips, nil, d.network, d.port)
}

// deadline returns the earliest of:
//   - now+Timeout
//   - d.Deadline
//   - the context's deadline
//
// Or zero, if none of Timeout, Deadline, or context's deadline is set.
func (d *DialWrap) deadline(ctx context.Context, now time.Time) (earliest time.Time) {
	// including negative, for historical reasons
	if d.dialer.Timeout != 0 {
		earliest = now.Add(d.dialer.Timeout + d.FirstConnectionTook())
	}
	if de, ok := ctx.Deadline(); ok {
		earliest = minNonzeroTime(earliest, de.Add(d.FirstConnectionTook()))
	}
	return earliest
}

// MultipathTCP is a getter for the MultipathTCP field
func (d *DialWrap) MultipathTCP() bool {
	return d.dialer.MultipathTCP()
}

// SetMultipathTCP is a setter for the MultipathTCP field
func (d *DialWrap) SetMultipathTCP(use bool) {
	d.dialer.SetMultipathTCP(use)
}

// dualStack is a getter for the dualStack field
func (d *DialWrap) dualStack() bool { return d.dialer.FallbackDelay >= 0 }

// fallbackDelay is a getter for the fallbackDelay field
func (d *DialWrap) fallbackDelay() time.Duration {
	if d.dialer.FallbackDelay > 0 {
		return d.dialer.FallbackDelay
	} else {
		return 300 * time.Millisecond
	}
}

// dialParallel races two copies of dialSerial, giving the first a
// head start. It returns the first established connection and
// closes the others. Otherwise it returns an error from the first
// primary address.
func (d *DialWrap) dialParallel(ctx context.Context, primaries, fallbacks []net.IP, network string, port string) (net.Conn, error) {
	if len(fallbacks) == 0 {
		return d.dialSerial(ctx, primaries, network, port)
	}

	returned := make(chan struct{})
	defer close(returned)

	results := make(chan dialResult) // unbuffered

	startRacer := func(ctx context.Context, primary bool) {
		ras := primaries
		if !primary {
			ras = fallbacks
		}
		c, err := d.dialSerial(ctx, ras, network, port)
		select {
		case results <- dialResult{Conn: c, error: err, primary: primary, done: true}:
		case <-returned:
			if c != nil {
				_ = c.Close()
			}
		}
	}

	var primary, fallback dialResult

	// Start the main racer.
	primaryCtx, primaryCancel := context.WithCancel(ctx)
	defer primaryCancel()
	go startRacer(primaryCtx, true)

	// Start the timer for the fallback racer.
	fallbackTimer := time.NewTimer(d.fallbackDelay())
	defer fallbackTimer.Stop()

	for {
		select {
		case <-fallbackTimer.C:
			fallbackCtx, fallbackCancel := context.WithCancel(ctx)
			defer fallbackCancel()
			go startRacer(fallbackCtx, false)

		case res := <-results:
			if res.error == nil {
				return res.Conn, nil
			}
			if res.primary {
				primary = res
			} else {
				fallback = res
			}
			if primary.done && fallback.done {
				return nil, primary.error
			}
			if res.primary && fallbackTimer.Stop() {
				// If we were able to stop the timer, that means it
				// was running (hadn't yet started the fallback), but
				// we just got an error on the primary path, so start
				// the fallback immediately (in 0 nanoseconds).
				fallbackTimer.Reset(0)
			}
		}
	}
}

// IPs returns the ips of the target
func (d *DialWrap) IPs() []net.IP {
	return slices.Clone(d.ips)
}

// Address returns ip and port of the target
// if multiple ips are present, it returns the first one
func (d *DialWrap) Address() (string, string) {
	if len(d.ips) == 0 {
		return "", ""
	}
	return d.ips[0].String(), d.port
}

// dialSerial connects to a list of addresses in sequence, returning
// either the first successful connection, or the first error.
func (d *DialWrap) dialSerial(ctx context.Context, ras []net.IP, network, port string) (net.Conn, error) {
	var firstErr error // The error from the first address is most relevant.

	for _, ra := range ras {
		select {
		case <-ctx.Done():
			// improve this error message
			return nil, ctx.Err()
		default:
		}

		c, err := d.dialer.DialContext(ctx, network, net.JoinHostPort(ra.String(), port))
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	if firstErr == nil {
		firstErr = errkit.Wrap(net.UnknownNetworkError(network), "dialSerial")
	}
	return nil, firstErr
}

func minNonzeroTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() || a.Before(b) {
		return a
	}
	return b
}

func (d *DialWrap) FirstConnectionTook() time.Duration {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.firstConnectionDuration
}

func (d *DialWrap) SetFirstConnectionDuration(dur time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.firstConnectionDuration = dur
}

// SetExpireConnAfter sets the duration after which a cached connection expires.
// If dur is 0, [DefaultConnExpiry] is used.
func (d *DialWrap) SetExpireConnAfter(dur time.Duration) {
	if dur == 0 {
		dur = DefaultConnExpiry
	}

	d.expireConnAfter = dur
}
