package routeros

import "github.com/go-routeros/routeros/proto"

type sentenceProcessor interface {
	processSentence(sen *proto.Sentence) (bool, error)
}

type replyCloser interface {
	close(err error)
}

// Async starts asynchronous mode and returns immediately.
func (c *Client) Async() <-chan error {
	c.mu.Lock()
	defer c.mu.Unlock()

	errC := make(chan error, 1)
	if c.async {
		errC <- errAlreadyAsync
		close(errC)
		return errC
	}
	c.async = true
	c.tags = make(map[string]sentenceProcessor)
	go c.asyncLoopChan(errC)
	return errC
}

func (c *Client) asyncLoopChan(errC chan<- error) {
	defer close(errC)
	// If c.Close() has been called, c.closing will be true, and
	// err will be “use of closed network connection”. Ignore that error.
	err := c.asyncLoop()
	if err != nil {
		c.mu.Lock()
		closing := c.closing
		c.mu.Unlock()
		if !closing {
			errC <- err
		}
	}
}

func (c *Client) asyncLoop() error {
	for {
		sen, err := c.r.ReadSentence()
		if err != nil {
			c.closeTags(err)
			return err
		}

		c.mu.Lock()
		r, ok := c.tags[sen.Tag]
		c.mu.Unlock()
		if !ok {
			continue
		}

		done, err := r.processSentence(sen)
		if done || err != nil {
			c.mu.Lock()
			delete(c.tags, sen.Tag)
			c.mu.Unlock()
			closeReply(r, err)
		}
	}
}

func (c *Client) closeTags(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, r := range c.tags {
		closeReply(r, err)
	}
	c.tags = nil
}

func closeReply(r sentenceProcessor, err error) {
	rr, ok := r.(replyCloser)
	if ok {
		rr.close(err)
	}
}
