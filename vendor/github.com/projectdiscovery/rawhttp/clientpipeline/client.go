package clientpipeline

// Original Source: https://github.com/valyala/fasthttp

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const DefaultMaxConnsPerHost = 512
const DefaultMaxIdleConnDuration = 10 * time.Second
const DefaultMaxIdemponentCallAttempts = 5
const defaultReadBufferSize = 4096
const defaultWriteBufferSize = 4096

type DialFunc func(addr string) (net.Conn, error)
type RetryIfFunc func(request *Request) bool

var (
	ErrNoFreeConns      = errors.New("no free connections available to host")
	ErrConnectionClosed = errors.New("the server closed connection before returning the first response byte. " +
		"Make sure the server returns 'Connection: close' response header before closing the connection")
	// ErrGetOnly is returned when server expects only GET requests,
	// but some other type of request came (Server.GetOnly option is true).
	ErrGetOnly = errors.New("non-GET request received")
)

type timeoutError struct {
}

func (e *timeoutError) Error() string {
	return "timeout"
}

func (e *timeoutError) Timeout() bool {
	return true
}

var (
	ErrTimeout = &timeoutError{}
)

func newClientTLSConfig(c *tls.Config, addr string) *tls.Config {
	if c == nil {
		c = &tls.Config{}
	} else {
		c = c.Clone()
	}

	if c.ClientSessionCache == nil {
		c.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	}

	if len(c.ServerName) == 0 {
		serverName := tlsServerName(addr)
		if serverName == "*" {
			c.InsecureSkipVerify = true
		} else {
			c.ServerName = serverName
		}
	}
	return c
}

func tlsServerName(addr string) string {
	if !strings.Contains(addr, ":") {
		return addr
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "*"
	}
	return host
}

// ErrTLSHandshakeTimeout indicates there is a timeout from tls handshake.
var ErrTLSHandshakeTimeout = errors.New("tls handshake timed out")

var timeoutErrorChPool sync.Pool

func tlsClientHandshake(rawConn net.Conn, tlsConfig *tls.Config, timeout time.Duration) (net.Conn, error) {
	tc := time.NewTimer(timeout)
	defer tc.Stop()

	var ch chan error
	chv := timeoutErrorChPool.Get()
	if chv == nil {
		chv = make(chan error)
	}
	ch = chv.(chan error)
	defer timeoutErrorChPool.Put(chv)

	conn := tls.Client(rawConn, tlsConfig)

	go func() {
		ch <- conn.Handshake()
	}()

	select {
	case <-tc.C:
		rawConn.Close()
		<-ch
		return nil, ErrTLSHandshakeTimeout
	case err := <-ch:
		if err != nil {
			rawConn.Close()
			return nil, err
		}
		return conn, nil
	}
}

func dialAddr(addr string, dial DialFunc, dialDualStack, isTLS bool, tlsConfig *tls.Config, timeout time.Duration) (net.Conn, error) {
	if dial == nil {
		if dialDualStack {
			dial = DialDualStack
		} else {
			dial = Dial
		}
		addr = addMissingPort(addr, isTLS)
	}
	conn, err := dial(addr)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		panic("BUG: DialFunc returned (nil, nil)")
	}
	_, isTLSAlready := conn.(*tls.Conn)
	if isTLS && !isTLSAlready {
		if timeout == 0 {
			return tls.Client(conn, tlsConfig), nil
		}
		return tlsClientHandshake(conn, tlsConfig, timeout)
	}
	return conn, nil
}

func addMissingPort(addr string, isTLS bool) string {
	n := strings.Index(addr, ":")
	if n >= 0 {
		return addr
	}
	port := 80
	if isTLS {
		port = 443
	}
	return net.JoinHostPort(addr, strconv.Itoa(port))
}

type PipelineClient struct {
	Addr                string
	MaxConns            int
	MaxPendingRequests  int
	MaxBatchDelay       time.Duration
	Dial                DialFunc
	DialDualStack       bool
	IsTLS               bool
	TLSConfig           *tls.Config
	MaxIdleConnDuration time.Duration
	ReadBufferSize      int
	WriteBufferSize     int
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration

	connClients     []*pipelineConnClient
	connClientsLock sync.Mutex
}

type pipelineConnClient struct {
	Addr                string
	MaxPendingRequests  int
	MaxBatchDelay       time.Duration
	Dial                DialFunc
	DialDualStack       bool
	IsTLS               bool
	TLSConfig           *tls.Config
	MaxIdleConnDuration time.Duration
	ReadBufferSize      int
	WriteBufferSize     int
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration

	workPool sync.Pool

	chLock sync.Mutex
	chW    chan *pipelineWork
	chR    chan *pipelineWork

	tlsConfigLock sync.Mutex
	tlsConfig     *tls.Config
}

type pipelineWork struct {
	req      *Request
	resp     *Response
	t        *time.Timer
	deadline time.Time
	err      error
	done     chan struct{}
}

func (c *PipelineClient) Do(req *Request, resp *Response) error {
	return c.getConnClient().Do(req, resp)
}

func (c *pipelineConnClient) Do(req *Request, resp *Response) error {
	c.init()

	w := acquirePipelineWork(&c.workPool, 0)
	w.req = req
	if resp != nil {
		w.resp = resp
	}

	// Put the request to outgoing queue
	select {
	case c.chW <- w:
	default:
		// Try substituting the oldest w with the current one.
		select {
		case wOld := <-c.chW:
			wOld.err = ErrPipelineOverflow
			wOld.done <- struct{}{}
		default:
		}
		select {
		case c.chW <- w:
		default:
			releasePipelineWork(&c.workPool, w)
			return ErrPipelineOverflow
		}
	}

	// Wait for the response
	<-w.done
	err := w.err

	releasePipelineWork(&c.workPool, w)

	return err
}

func (c *PipelineClient) getConnClient() *pipelineConnClient {
	c.connClientsLock.Lock()
	cc := c.getConnClientUnlocked()
	c.connClientsLock.Unlock()
	return cc
}

func (c *PipelineClient) getConnClientUnlocked() *pipelineConnClient {
	if len(c.connClients) == 0 {
		return c.newConnClient()
	}

	// Return the client with the minimum number of pending requests.
	minCC := c.connClients[0]
	minReqs := minCC.PendingRequests()
	if minReqs == 0 {
		return minCC
	}
	for i := 1; i < len(c.connClients); i++ {
		cc := c.connClients[i]
		reqs := cc.PendingRequests()
		if reqs == 0 {
			return cc
		}
		if reqs < minReqs {
			minCC = cc
			minReqs = reqs
		}
	}

	maxConns := c.MaxConns
	if maxConns <= 0 {
		maxConns = 1
	}
	if len(c.connClients) < maxConns {
		return c.newConnClient()
	}
	return minCC
}

func (c *PipelineClient) newConnClient() *pipelineConnClient {
	cc := &pipelineConnClient{
		Addr:                c.Addr,
		MaxPendingRequests:  c.MaxPendingRequests,
		MaxBatchDelay:       c.MaxBatchDelay,
		Dial:                c.Dial,
		DialDualStack:       c.DialDualStack,
		IsTLS:               c.IsTLS,
		TLSConfig:           c.TLSConfig,
		MaxIdleConnDuration: c.MaxIdleConnDuration,
		ReadBufferSize:      c.ReadBufferSize,
		WriteBufferSize:     c.WriteBufferSize,
		ReadTimeout:         c.ReadTimeout,
		WriteTimeout:        c.WriteTimeout,
	}
	c.connClients = append(c.connClients, cc)
	return cc
}

var ErrPipelineOverflow = errors.New("pipelined requests' queue has been overflown. Increase MaxConns and/or MaxPendingRequests")

const DefaultMaxPendingRequests = 1024

func (c *pipelineConnClient) init() {
	c.chLock.Lock()
	if c.chR == nil {
		maxPendingRequests := c.MaxPendingRequests
		if maxPendingRequests <= 0 {
			maxPendingRequests = DefaultMaxPendingRequests
		}
		c.chR = make(chan *pipelineWork, maxPendingRequests)
		if c.chW == nil {
			c.chW = make(chan *pipelineWork, maxPendingRequests)
		}
		go func() {
			// Keep restarting the worker if it fails (connection errors for example).
			for {
				if err := c.worker(); err != nil {
					w := <-c.chW
					w.err = err
					w.done <- struct{}{}
				} else {
					c.chLock.Lock()
					stop := len(c.chR) == 0 && len(c.chW) == 0
					if !stop {
						c.chR = nil
						c.chW = nil
					}
					c.chLock.Unlock()

					if stop {
						break
					}
				}
			}
		}()
	}
	c.chLock.Unlock()
}

func (c *pipelineConnClient) worker() error {
	tlsConfig := c.cachedTLSConfig()
	conn, err := dialAddr(c.Addr, c.Dial, c.DialDualStack, c.IsTLS, tlsConfig, c.WriteTimeout)
	if err != nil {
		return err
	}

	// Start reader and writer
	stopW := make(chan struct{})
	doneW := make(chan error)
	go func() {
		doneW <- c.writer(conn, stopW)
	}()
	stopR := make(chan struct{})
	doneR := make(chan error)
	go func() {
		doneR <- c.reader(conn, stopR)
	}()

	// Wait until reader and writer are stopped
	select {
	case err = <-doneW:
		conn.Close()
		close(stopR)
		<-doneR
	case err = <-doneR:
		conn.Close()
		close(stopW)
		<-doneW
	}

	// Notify pending readers
	for len(c.chR) > 0 {
		w := <-c.chR
		w.err = errPipelineConnStopped
		w.done <- struct{}{}
	}

	return err
}

func (c *pipelineConnClient) cachedTLSConfig() *tls.Config {
	if !c.IsTLS {
		return nil
	}

	c.tlsConfigLock.Lock()
	cfg := c.tlsConfig
	if cfg == nil {
		cfg = newClientTLSConfig(c.TLSConfig, c.Addr)
		c.tlsConfig = cfg
	}
	c.tlsConfigLock.Unlock()

	return cfg
}

func (c *pipelineConnClient) writer(conn net.Conn, stopCh <-chan struct{}) error {
	writeBufferSize := c.WriteBufferSize
	if writeBufferSize <= 0 {
		writeBufferSize = defaultWriteBufferSize
	}
	bw := bufio.NewWriterSize(conn, writeBufferSize)
	defer bw.Flush()
	chR := c.chR
	chW := c.chW
	writeTimeout := c.WriteTimeout

	maxIdleConnDuration := c.MaxIdleConnDuration
	if maxIdleConnDuration <= 0 {
		maxIdleConnDuration = DefaultMaxIdleConnDuration
	}
	maxBatchDelay := c.MaxBatchDelay

	var (
		stopTimer      = time.NewTimer(time.Hour)
		flushTimer     = time.NewTimer(time.Hour)
		flushTimerCh   <-chan time.Time
		instantTimerCh = make(chan time.Time)

		w   *pipelineWork
		err error
	)
	close(instantTimerCh)
	for {
	againChW:
		select {
		case w = <-chW:
			// Fast path: len(chW) > 0
		default:
			// Slow path
			stopTimer.Reset(maxIdleConnDuration)
			select {
			case w = <-chW:
			case <-stopTimer.C:
				return nil
			case <-stopCh:
				return nil
			case <-flushTimerCh:
				if err = bw.Flush(); err != nil {
					return err
				}
				flushTimerCh = nil
				goto againChW
			}
		}

		if !w.deadline.IsZero() && time.Since(w.deadline) >= 0 {
			w.err = ErrTimeout
			w.done <- struct{}{}
			continue
		}

		if writeTimeout > 0 {
			// Set Deadline every time, since golang has fixed the performance issue
			// See https://github.com/golang/go/issues/15133#issuecomment-271571395 for details
			currentTime := time.Now()
			if err = conn.SetWriteDeadline(currentTime.Add(writeTimeout)); err != nil {
				w.err = err
				w.done <- struct{}{}
				return err
			}
		}
		if err = w.req.Write(bw); err != nil {
			w.err = err
			w.done <- struct{}{}
			return err
		}
		if flushTimerCh == nil && (len(chW) == 0 || len(chR) == cap(chR)) {
			if maxBatchDelay > 0 {
				flushTimer.Reset(maxBatchDelay)
				flushTimerCh = flushTimer.C
			} else {
				flushTimerCh = instantTimerCh
			}
		}

	againChR:
		select {
		case chR <- w:
			// Fast path: len(chR) < cap(chR)
		default:
			// Slow path
			select {
			case chR <- w:
			case <-stopCh:
				w.err = errPipelineConnStopped
				w.done <- struct{}{}
				return nil
			case <-flushTimerCh:
				if err = bw.Flush(); err != nil {
					w.err = err
					w.done <- struct{}{}
					return err
				}
				flushTimerCh = nil
				goto againChR
			}
		}
	}
}

func (c *pipelineConnClient) reader(conn net.Conn, stopCh <-chan struct{}) error {
	readBufferSize := c.ReadBufferSize
	if readBufferSize <= 0 {
		readBufferSize = defaultReadBufferSize
	}
	br := bufio.NewReaderSize(conn, readBufferSize)
	chR := c.chR
	readTimeout := c.ReadTimeout

	var (
		w   *pipelineWork
		err error
	)
	for {
		select {
		case w = <-chR:
			// Fast path: len(chR) > 0
		default:
			// Slow path
			select {
			case w = <-chR:
			case <-stopCh:
				return nil
			}
		}

		if readTimeout > 0 {
			// Set Deadline every time, since golang has fixed the performance issue
			// See https://github.com/golang/go/issues/15133#issuecomment-271571395 for details
			currentTime := time.Now()
			if err = conn.SetReadDeadline(currentTime.Add(readTimeout)); err != nil {
				w.err = err
				w.done <- struct{}{}
				return err
			}
		}
		if err = w.resp.Read(br); err != nil {
			w.err = err
			w.done <- struct{}{}
			return err
		}

		w.done <- struct{}{}
	}
}

func (c *PipelineClient) PendingRequests() int {
	c.connClientsLock.Lock()
	n := 0
	for _, cc := range c.connClients {
		n += cc.PendingRequests()
	}
	c.connClientsLock.Unlock()
	return n
}

func (c *pipelineConnClient) PendingRequests() int {
	c.init()

	c.chLock.Lock()
	n := len(c.chR) + len(c.chW)
	c.chLock.Unlock()
	return n
}

var errPipelineConnStopped = errors.New("pipeline connection has been stopped")

func acquirePipelineWork(pool *sync.Pool, timeout time.Duration) *pipelineWork {
	v := pool.Get()
	if v == nil {
		v = &pipelineWork{
			done: make(chan struct{}, 1),
		}
	}
	w := v.(*pipelineWork)
	if timeout > 0 {
		if w.t == nil {
			w.t = time.NewTimer(timeout)
		} else {
			w.t.Reset(timeout)
		}
		w.deadline = time.Now().Add(timeout)
	}

	return w
}

func releasePipelineWork(pool *sync.Pool, w *pipelineWork) {
	if w.t != nil {
		w.t.Stop()
	}
	w.req = nil
	w.resp = nil
	w.err = nil
	pool.Put(w)
}
