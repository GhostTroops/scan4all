package routeros

import (
	"fmt"

	"github.com/go-routeros/routeros/proto"
)

type asyncReply struct {
	chanReply
	Reply
}

// Run simply calls RunArgs().
func (c *Client) Run(sentence ...string) (*Reply, error) {
	return c.RunArgs(sentence)
}

// RunArgs sends a sentence to the RouterOS device and waits for the reply.
func (c *Client) RunArgs(sentence []string) (*Reply, error) {
	c.w.BeginSentence()
	for _, word := range sentence {
		c.w.WriteWord(word)
	}
	if !c.async {
		return c.endCommandSync()
	}
	a, err := c.endCommandAsync()
	if err != nil {
		return nil, err
	}
	for range a.reC {
	}
	return &a.Reply, a.err
}

func (c *Client) endCommandSync() (*Reply, error) {
	err := c.w.EndSentence()
	if err != nil {
		return nil, err
	}
	return c.readReply()
}

func (c *Client) endCommandAsync() (*asyncReply, error) {
	c.nextTag++
	a := &asyncReply{}
	a.reC = make(chan *proto.Sentence)
	a.tag = fmt.Sprintf("r%d", c.nextTag)
	c.w.WriteWord(".tag=" + a.tag)

	c.mu.Lock()
	defer c.mu.Unlock()

	err := c.w.EndSentence()
	if err != nil {
		return nil, err
	}
	if c.tags == nil {
		return nil, errAsyncLoopEnded
	}
	c.tags[a.tag] = a
	return a, nil
}
