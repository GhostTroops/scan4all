package irc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// ClientConfig is a structure used to configure a Client.
type ClientConfig struct {
	// General connection information.
	Nick string
	Pass string
	User string
	Name string

	// Connection settings
	PingFrequency time.Duration
	PingTimeout   time.Duration

	// SendLimit is how frequent messages can be sent. If this is zero,
	// there will be no limit.
	SendLimit time.Duration

	// SendBurst is the number of messages which can be sent in a burst.
	SendBurst int

	// Handler is used for message dispatching.
	Handler Handler
}

type cap struct {
	// Requested means that this cap was requested by the user
	Requested bool

	// Required will be true if this cap is non-optional
	Required bool

	// Enabled means that this cap was accepted by the server
	Enabled bool

	// Available means that the server supports this cap
	Available bool
}

// Client is a wrapper around Conn which is designed to make common operations
// much simpler.
type Client struct {
	*Conn
	rwc    io.ReadWriteCloser
	config ClientConfig

	// Internal state
	currentNick           string
	limiter               chan struct{}
	incomingPongChan      chan string
	errChan               chan error
	caps                  map[string]cap
	remainingCapResponses int
	connected             bool
}

// NewClient creates a client given an io stream and a client config.
func NewClient(rwc io.ReadWriteCloser, config ClientConfig) *Client {
	c := &Client{
		Conn:    NewConn(rwc),
		rwc:     rwc,
		config:  config,
		errChan: make(chan error, 1),
		caps:    make(map[string]cap),
	}

	// Replace the writer writeCallback with one of our own
	c.Conn.Writer.writeCallback = c.writeCallback

	return c
}

func (c *Client) writeCallback(w *Writer, line string) error {
	if c.limiter != nil {
		<-c.limiter
	}

	_, err := w.writer.Write([]byte(line + "\r\n"))
	if err != nil {
		c.sendError(err)
	}
	return err
}

// maybeStartLimiter will start a ticker which will limit how quickly messages
// can be written to the connection if the SendLimit is set in the config.
func (c *Client) maybeStartLimiter(wg *sync.WaitGroup, exiting chan struct{}) {
	if c.config.SendLimit == 0 {
		return
	}

	wg.Add(1)

	// If SendBurst is 0, this will be unbuffered, so keep that in mind.
	c.limiter = make(chan struct{}, c.config.SendBurst)
	limitTick := time.NewTicker(c.config.SendLimit)

	go func() {
		defer wg.Done()

		var done bool
		for !done {
			select {
			case <-limitTick.C:
				select {
				case c.limiter <- struct{}{}:
				default:
				}
			case <-exiting:
				done = true
			}
		}

		limitTick.Stop()
		close(c.limiter)
		c.limiter = nil
	}()
}

// maybeStartPingLoop will start a goroutine to send out PING messages at the
// PingFrequency in the config if the frequency is not 0.
func (c *Client) maybeStartPingLoop(wg *sync.WaitGroup, exiting chan struct{}) {
	if c.config.PingFrequency <= 0 {
		return
	}

	wg.Add(1)

	c.incomingPongChan = make(chan string, 5)

	go func() {
		defer wg.Done()

		pingHandlers := make(map[string]chan struct{})
		ticker := time.NewTicker(c.config.PingFrequency)

		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Each time we get a tick, we send off a ping and start a
				// goroutine to handle the pong.
				timestamp := time.Now().Unix()
				pongChan := make(chan struct{}, 1)
				pingHandlers[fmt.Sprintf("%d", timestamp)] = pongChan
				wg.Add(1)
				go c.handlePing(timestamp, pongChan, wg, exiting)
			case data := <-c.incomingPongChan:
				// Make sure the pong gets routed to the correct
				// goroutine.

				c := pingHandlers[data]
				delete(pingHandlers, data)

				if c != nil {
					c <- struct{}{}
				}
			case <-exiting:
				return
			}
		}
	}()
}

func (c *Client) handlePing(timestamp int64, pongChan chan struct{}, wg *sync.WaitGroup, exiting chan struct{}) {
	defer wg.Done()

	c.Writef("PING :%d", timestamp)

	timer := time.NewTimer(c.config.PingTimeout)
	defer timer.Stop()

	select {
	case <-timer.C:
		c.sendError(errors.New("ping timeout"))
	case <-pongChan:
		return
	case <-exiting:
		return
	}
}

// maybeStartCapHandshake will run a CAP LS and all the relevant CAP REQ
// commands if there are any CAPs requested.
func (c *Client) maybeStartCapHandshake() {
	if len(c.caps) == 0 {
		return
	}

	c.Write("CAP LS")
	c.remainingCapResponses = 1 // We count the CAP LS response as a normal response
	for key, cap := range c.caps {
		if cap.Requested {
			c.Writef("CAP REQ :%s", key)
			c.remainingCapResponses++
		}
	}
}

// CapRequest allows you to request IRCv3 capabilities from the server during
// the handshake. The behavior is undefined if this is called before the
// handshake completes so it is recommended that this be called before Run. If
// the CAP is marked as required, the client will exit if that CAP could not be
// negotiated during the handshake.
func (c *Client) CapRequest(capName string, required bool) {
	cap := c.caps[capName]
	cap.Requested = true
	cap.Required = cap.Required || required
	c.caps[capName] = cap
}

// CapEnabled allows you to check if a CAP is enabled for this connection. Note
// that it will not be populated until after the CAP handshake is done, so it is
// recommended to wait to check this until after a message like 001.
func (c *Client) CapEnabled(capName string) bool {
	return c.caps[capName].Enabled
}

// CapAvailable allows you to check if a CAP is available on this server. Note
// that it will not be populated until after the CAP handshake is done, so it is
// recommended to wait to check this until after a message like 001.
func (c *Client) CapAvailable(capName string) bool {
	return c.caps[capName].Available
}

func (c *Client) sendError(err error) {
	select {
	case c.errChan <- err:
	default:
	}
}

func (c *Client) startReadLoop(wg *sync.WaitGroup, exiting chan struct{}) {
	wg.Add(1)

	go func() {
		defer wg.Done()

		for {
			select {
			case <-exiting:
				return
			default:
				m, err := c.ReadMessage()
				if err != nil {
					c.sendError(err)
					break
				}

				if f, ok := clientFilters[m.Command]; ok {
					f(c, m)
				}

				if c.config.Handler != nil {
					c.config.Handler.Handle(c, m)
				}
			}
		}
	}()
}

// Run starts the main loop for this IRC connection. Note that it may break in
// strange and unexpected ways if it is called again before the first connection
// exits.
func (c *Client) Run() error {
	return c.RunContext(context.TODO())
}

// RunContext is the same as Run but a context.Context can be passed in for
// cancelation.
func (c *Client) RunContext(ctx context.Context) error {
	// exiting is used by the main goroutine here to ensure any sub-goroutines
	// get closed when exiting.
	exiting := make(chan struct{})
	var wg sync.WaitGroup

	c.maybeStartLimiter(&wg, exiting)
	c.maybeStartPingLoop(&wg, exiting)

	c.currentNick = c.config.Nick

	if c.config.Pass != "" {
		c.Writef("PASS :%s", c.config.Pass)
	}

	c.maybeStartCapHandshake()

	// This feels wrong because it results in CAP LS, CAP REQ, NICK, USER, CAP
	// END, but it works and lets us keep the code a bit simpler.
	c.Writef("NICK :%s", c.config.Nick)
	c.Writef("USER %s 0 * :%s", c.config.User, c.config.Name)

	// Now that the handshake is pretty much done, we can start listening for
	// messages.
	c.startReadLoop(&wg, exiting)

	// Wait for an error from any goroutine or for the context to time out, then
	// signal we're exiting and wait for the goroutines to exit.
	var err error
	select {
	case err = <-c.errChan:
	case <-ctx.Done():
	}

	close(exiting)
	c.rwc.Close()
	wg.Wait()

	return err
}

// CurrentNick returns what the nick of the client is known to be at this point
// in time.
func (c *Client) CurrentNick() string {
	return c.currentNick
}

// FromChannel takes a Message representing a PRIVMSG and returns if that
// message came from a channel or directly from a user.
func (c *Client) FromChannel(m *Message) bool {
	if len(m.Params) < 1 {
		return false
	}

	// The first param is the target, so if this doesn't match the current nick,
	// the message came from a channel.
	return m.Params[0] != c.currentNick
}
