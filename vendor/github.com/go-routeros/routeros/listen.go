package routeros

import (
	"fmt"

	"github.com/go-routeros/routeros/proto"
)

// ListenReply is the struct returned by the Listen*() functions.
// When the channel returned by Chan() is closed, Done is set to the
// RouterOS sentence that caused it to be closed.
type ListenReply struct {
	chanReply
	Done *proto.Sentence
	c    *Client
}

// Chan returns a channel for receiving !re RouterOS sentences.
// To close the channel, call Cancel() on l.
func (l *ListenReply) Chan() <-chan *proto.Sentence {
	return l.reC
}

// Cancel sends a cancel command to the RouterOS device.
func (l *ListenReply) Cancel() (*Reply, error) {
	return l.c.Run("/cancel", "=tag="+l.tag)
}

// Listen simply calls ListenArgsQueue() with queueSize set to c.Queue.
func (c *Client) Listen(sentence ...string) (*ListenReply, error) {
	return c.ListenArgsQueue(sentence, c.Queue)
}

// ListenArgs simply calls ListenArgsQueue() with queueSize set to c.Queue.
func (c *Client) ListenArgs(sentence []string) (*ListenReply, error) {
	return c.ListenArgsQueue(sentence, c.Queue)
}

// ListenArgsQueue sends a sentence to the RouterOS device and returns immediately.
func (c *Client) ListenArgsQueue(sentence []string, queueSize int) (*ListenReply, error) {
	if !c.async {
		c.Async()
	}

	c.nextTag++
	l := &ListenReply{c: c}
	l.tag = fmt.Sprintf("l%d", c.nextTag)
	l.reC = make(chan *proto.Sentence, queueSize)

	c.w.BeginSentence()
	for _, word := range sentence {
		c.w.WriteWord(word)
	}
	c.w.WriteWord(".tag=" + l.tag)

	c.mu.Lock()
	defer c.mu.Unlock()

	err := c.w.EndSentence()
	if err != nil {
		return nil, err
	}
	if c.tags == nil {
		return nil, errAsyncLoopEnded
	}
	c.tags[l.tag] = l
	return l, nil
}

func (l *ListenReply) processSentence(sen *proto.Sentence) (bool, error) {
	switch sen.Word {
	case "!re":
		l.reC <- sen
	case "!done":
		l.Done = sen
		return true, nil
	case "!trap":
		if sen.Map["category"] == "2" {
			l.Done = sen // "execution of command interrupted"
			return true, nil
		}
		return true, &DeviceError{sen}
	case "!fatal":
		return true, &DeviceError{sen}
	case "":
		// API docs say that empty sentences should be ignored
	default:
		return true, &UnknownReplyError{sen}
	}
	return false, nil
}
