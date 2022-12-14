package sctp

import (
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"

	"github.com/pion/logging"
)

const (
	// ReliabilityTypeReliable is used for reliable transmission
	ReliabilityTypeReliable byte = 0
	// ReliabilityTypeRexmit is used for partial reliability by retransmission count
	ReliabilityTypeRexmit byte = 1
	// ReliabilityTypeTimed is used for partial reliability by retransmission duration
	ReliabilityTypeTimed byte = 2
)

// StreamState is an enum for SCTP Stream state field
// This field identifies the state of stream.
type StreamState int

// StreamState enums
const (
	StreamStateOpen    StreamState = iota // Stream object starts with StreamStateOpen
	StreamStateClosing                    // Outgoing stream is being reset
	StreamStateClosed                     // Stream has been closed
)

func (ss StreamState) String() string {
	switch ss {
	case StreamStateOpen:
		return "open"
	case StreamStateClosing:
		return "closing"
	case StreamStateClosed:
		return "closed"
	}
	return "unknown"
}

var (
	errOutboundPacketTooLarge = errors.New("outbound packet larger than maximum message size")
	errStreamClosed           = errors.New("stream closed")
)

// Stream represents an SCTP stream
type Stream struct {
	association         *Association
	lock                sync.RWMutex
	streamIdentifier    uint16
	defaultPayloadType  PayloadProtocolIdentifier
	reassemblyQueue     *reassemblyQueue
	sequenceNumber      uint16
	readNotifier        *sync.Cond
	readErr             error
	unordered           bool
	reliabilityType     byte
	reliabilityValue    uint32
	bufferedAmount      uint64
	bufferedAmountLow   uint64
	onBufferedAmountLow func()
	state               StreamState
	log                 logging.LeveledLogger
	name                string
}

// StreamIdentifier returns the Stream identifier associated to the stream.
func (s *Stream) StreamIdentifier() uint16 {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.streamIdentifier
}

// SetDefaultPayloadType sets the default payload type used by Write.
func (s *Stream) SetDefaultPayloadType(defaultPayloadType PayloadProtocolIdentifier) {
	atomic.StoreUint32((*uint32)(&s.defaultPayloadType), uint32(defaultPayloadType))
}

// SetReliabilityParams sets reliability parameters for this stream.
func (s *Stream) SetReliabilityParams(unordered bool, relType byte, relVal uint32) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.setReliabilityParams(unordered, relType, relVal)
}

// setReliabilityParams sets reliability parameters for this stream.
// The caller should hold the lock.
func (s *Stream) setReliabilityParams(unordered bool, relType byte, relVal uint32) {
	s.log.Debugf("[%s] reliability params: ordered=%v type=%d value=%d",
		s.name, !unordered, relType, relVal)
	s.unordered = unordered
	s.reliabilityType = relType
	s.reliabilityValue = relVal
}

// Read reads a packet of len(p) bytes, dropping the Payload Protocol Identifier.
// Returns EOF when the stream is reset or an error if the stream is closed
// otherwise.
func (s *Stream) Read(p []byte) (int, error) {
	n, _, err := s.ReadSCTP(p)
	return n, err
}

// ReadSCTP reads a packet of len(p) bytes and returns the associated Payload
// Protocol Identifier.
// Returns EOF when the stream is reset or an error if the stream is closed
// otherwise.
func (s *Stream) ReadSCTP(p []byte) (int, PayloadProtocolIdentifier, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for {
		n, ppi, err := s.reassemblyQueue.read(p)
		if err == nil {
			return n, ppi, nil
		} else if errors.Is(err, io.ErrShortBuffer) {
			return 0, PayloadProtocolIdentifier(0), err
		}

		err = s.readErr
		if err != nil {
			return 0, PayloadProtocolIdentifier(0), err
		}

		s.readNotifier.Wait()
	}
}

func (s *Stream) handleData(pd *chunkPayloadData) {
	s.lock.Lock()
	defer s.lock.Unlock()

	var readable bool
	if s.reassemblyQueue.push(pd) {
		readable = s.reassemblyQueue.isReadable()
		s.log.Debugf("[%s] reassemblyQueue readable=%v", s.name, readable)
		if readable {
			s.log.Debugf("[%s] readNotifier.signal()", s.name)
			s.readNotifier.Signal()
			s.log.Debugf("[%s] readNotifier.signal() done", s.name)
		}
	}
}

func (s *Stream) handleForwardTSNForOrdered(ssn uint16) {
	var readable bool

	func() {
		s.lock.Lock()
		defer s.lock.Unlock()

		if s.unordered {
			return // unordered chunks are handled by handleForwardUnordered method
		}

		// Remove all chunks older than or equal to the new TSN from
		// the reassemblyQueue.
		s.reassemblyQueue.forwardTSNForOrdered(ssn)
		readable = s.reassemblyQueue.isReadable()
	}()

	// Notify the reader asynchronously if there's a data chunk to read.
	if readable {
		s.readNotifier.Signal()
	}
}

func (s *Stream) handleForwardTSNForUnordered(newCumulativeTSN uint32) {
	var readable bool

	func() {
		s.lock.Lock()
		defer s.lock.Unlock()

		if !s.unordered {
			return // ordered chunks are handled by handleForwardTSNOrdered method
		}

		// Remove all chunks older than or equal to the new TSN from
		// the reassemblyQueue.
		s.reassemblyQueue.forwardTSNForUnordered(newCumulativeTSN)
		readable = s.reassemblyQueue.isReadable()
	}()

	// Notify the reader asynchronously if there's a data chunk to read.
	if readable {
		s.readNotifier.Signal()
	}
}

// Write writes len(p) bytes from p with the default Payload Protocol Identifier
func (s *Stream) Write(p []byte) (n int, err error) {
	ppi := PayloadProtocolIdentifier(atomic.LoadUint32((*uint32)(&s.defaultPayloadType)))
	return s.WriteSCTP(p, ppi)
}

// WriteSCTP writes len(p) bytes from p to the DTLS connection
func (s *Stream) WriteSCTP(p []byte, ppi PayloadProtocolIdentifier) (int, error) {
	maxMessageSize := s.association.MaxMessageSize()
	if len(p) > int(maxMessageSize) {
		return 0, fmt.Errorf("%w: %v", errOutboundPacketTooLarge, math.MaxUint16)
	}

	if s.State() != StreamStateOpen {
		return 0, errStreamClosed
	}

	chunks := s.packetize(p, ppi)
	n := len(p)
	err := s.association.sendPayloadData(chunks)
	if err != nil {
		return n, errStreamClosed
	}
	return n, nil
}

func (s *Stream) packetize(raw []byte, ppi PayloadProtocolIdentifier) []*chunkPayloadData {
	s.lock.Lock()
	defer s.lock.Unlock()

	i := uint32(0)
	remaining := uint32(len(raw))

	// From draft-ietf-rtcweb-data-protocol-09, section 6:
	//   All Data Channel Establishment Protocol messages MUST be sent using
	//   ordered delivery and reliable transmission.
	unordered := ppi != PayloadTypeWebRTCDCEP && s.unordered

	var chunks []*chunkPayloadData
	var head *chunkPayloadData
	for remaining != 0 {
		fragmentSize := min32(s.association.maxPayloadSize, remaining)

		// Copy the userdata since we'll have to store it until acked
		// and the caller may re-use the buffer in the mean time
		userData := make([]byte, fragmentSize)
		copy(userData, raw[i:i+fragmentSize])

		chunk := &chunkPayloadData{
			streamIdentifier:     s.streamIdentifier,
			userData:             userData,
			unordered:            unordered,
			beginningFragment:    i == 0,
			endingFragment:       remaining-fragmentSize == 0,
			immediateSack:        false,
			payloadType:          ppi,
			streamSequenceNumber: s.sequenceNumber,
			head:                 head,
		}

		if head == nil {
			head = chunk
		}

		chunks = append(chunks, chunk)

		remaining -= fragmentSize
		i += fragmentSize
	}

	// RFC 4960 Sec 6.6
	// Note: When transmitting ordered and unordered data, an endpoint does
	// not increment its Stream Sequence Number when transmitting a DATA
	// chunk with U flag set to 1.
	if !unordered {
		s.sequenceNumber++
	}

	s.bufferedAmount += uint64(len(raw))
	s.log.Tracef("[%s] bufferedAmount = %d", s.name, s.bufferedAmount)

	return chunks
}

// Close closes the write-direction of the stream.
// Future calls to Write are not permitted after calling Close.
func (s *Stream) Close() error {
	if sid, resetOutbound := func() (uint16, bool) {
		s.lock.Lock()
		defer s.lock.Unlock()

		s.log.Debugf("[%s] Close: state=%s", s.name, s.state.String())

		if s.state == StreamStateOpen {
			if s.readErr == nil {
				s.state = StreamStateClosing
			} else {
				s.state = StreamStateClosed
			}
			s.log.Debugf("[%s] state change: open => %s", s.name, s.state.String())
			return s.streamIdentifier, true
		}
		return s.streamIdentifier, false
	}(); resetOutbound {
		// Reset the outgoing stream
		// https://tools.ietf.org/html/rfc6525
		return s.association.sendResetRequest(sid)
	}

	return nil
}

// BufferedAmount returns the number of bytes of data currently queued to be sent over this stream.
func (s *Stream) BufferedAmount() uint64 {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.bufferedAmount
}

// BufferedAmountLowThreshold returns the number of bytes of buffered outgoing data that is
// considered "low." Defaults to 0.
func (s *Stream) BufferedAmountLowThreshold() uint64 {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.bufferedAmountLow
}

// SetBufferedAmountLowThreshold is used to update the threshold.
// See BufferedAmountLowThreshold().
func (s *Stream) SetBufferedAmountLowThreshold(th uint64) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.bufferedAmountLow = th
}

// OnBufferedAmountLow sets the callback handler which would be called when the number of
// bytes of outgoing data buffered is lower than the threshold.
func (s *Stream) OnBufferedAmountLow(f func()) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.onBufferedAmountLow = f
}

// This method is called by association's readLoop (go-)routine to notify this stream
// of the specified amount of outgoing data has been delivered to the peer.
func (s *Stream) onBufferReleased(nBytesReleased int) {
	if nBytesReleased <= 0 {
		return
	}

	s.lock.Lock()

	fromAmount := s.bufferedAmount

	if s.bufferedAmount < uint64(nBytesReleased) {
		s.bufferedAmount = 0
		s.log.Errorf("[%s] released buffer size %d should be <= %d",
			s.name, nBytesReleased, s.bufferedAmount)
	} else {
		s.bufferedAmount -= uint64(nBytesReleased)
	}

	s.log.Tracef("[%s] bufferedAmount = %d", s.name, s.bufferedAmount)

	if s.onBufferedAmountLow != nil && fromAmount > s.bufferedAmountLow && s.bufferedAmount <= s.bufferedAmountLow {
		f := s.onBufferedAmountLow
		s.lock.Unlock()
		f()
		return
	}

	s.lock.Unlock()
}

func (s *Stream) getNumBytesInReassemblyQueue() int {
	// No lock is required as it reads the size with atomic load function.
	return s.reassemblyQueue.getNumBytes()
}

func (s *Stream) onInboundStreamReset() {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.log.Debugf("[%s] onInboundStreamReset: state=%s", s.name, s.state.String())

	// No more inbound data to read. Unblock the read with io.EOF.
	// This should cause DCEP layer (datachannel package) to call Close() which
	// will reset outgoing stream also.

	// See RFC 8831 section 6.7:
	//	if one side decides to close the data channel, it resets the corresponding
	//	outgoing stream.  When the peer sees that an incoming stream was
	//	reset, it also resets its corresponding outgoing stream.  Once this
	//	is completed, the data channel is closed.

	s.readErr = io.EOF
	s.readNotifier.Broadcast()

	if s.state == StreamStateClosing {
		s.log.Debugf("[%s] state change: closing => closed", s.name)
		s.state = StreamStateClosed
	}
}

// State return the stream state.
func (s *Stream) State() StreamState {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.state
}
