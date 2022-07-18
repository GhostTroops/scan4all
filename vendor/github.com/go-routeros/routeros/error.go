package routeros

import (
	"errors"

	"github.com/go-routeros/routeros/proto"
)

var (
	errAlreadyAsync   = errors.New("Async() has already been called")
	errAsyncLoopEnded = errors.New("Async() loop has ended - probably read error")
)

// UnknownReplyError records the sentence whose Word is unknown.
type UnknownReplyError struct {
	Sentence *proto.Sentence
}

func (err *UnknownReplyError) Error() string {
	return "unknown RouterOS reply word: " + err.Sentence.Word
}

// DeviceError records the sentence containing the error received from the device.
// The sentence may have Word !trap or !fatal.
type DeviceError struct {
	Sentence *proto.Sentence
}

func (err *DeviceError) Error() string {
	m := err.Sentence.Map["message"]
	if m == "" {
		m = "unknown error: " + err.Sentence.String()
	}
	return "from RouterOS device: " + m
}
