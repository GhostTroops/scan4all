package routeros

import "github.com/go-routeros/routeros/proto"

// chanReply is shared between ListenReply and AsyncReply.
type chanReply struct {
	tag string
	err error
	reC chan *proto.Sentence
}

// Err returns the first error that happened processing sentences with tag.
func (a *chanReply) Err() error {
	return a.err
}

func (a *chanReply) close(err error) {
	if a.err == nil {
		a.err = err
	}
	close(a.reC)
}
