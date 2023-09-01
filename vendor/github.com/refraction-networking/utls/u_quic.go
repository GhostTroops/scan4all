// Copyright 2023 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"errors"
)

// A UQUICConn represents a connection which uses a QUIC implementation as the underlying
// transport as described in RFC 9001.
//
// Methods of UQUICConn are not safe for concurrent use.
type UQUICConn struct {
	conn *UConn

	sessionTicketSent bool
}

// QUICClient returns a new TLS client side connection using QUICTransport as the
// underlying transport. The config cannot be nil.
//
// The config's MinVersion must be at least TLS 1.3.
func UQUICClient(config *QUICConfig, clientHelloID ClientHelloID) *UQUICConn {
	return newUQUICConn(UClient(nil, config.TLSConfig, clientHelloID))
}

func newUQUICConn(uconn *UConn) *UQUICConn {
	uconn.quic = &quicState{
		signalc:  make(chan struct{}),
		blockedc: make(chan struct{}),
	}
	uconn.quic.events = uconn.quic.eventArr[:0]
	return &UQUICConn{
		conn: uconn,
	}
}

// Start starts the client or server handshake protocol.
// It may produce connection events, which may be read with NextEvent.
//
// Start must be called at most once.
func (q *UQUICConn) Start(ctx context.Context) error {
	if q.conn.quic.started {
		return quicError(errors.New("tls: Start called more than once"))
	}
	q.conn.quic.started = true
	if q.conn.config.MinVersion < VersionTLS13 {
		return quicError(errors.New("tls: Config MinVersion must be at least TLS 1.13"))
	}
	go q.conn.HandshakeContext(ctx)
	if _, ok := <-q.conn.quic.blockedc; !ok {
		return q.conn.handshakeErr
	}
	return nil
}

func (q *UQUICConn) ApplyPreset(p *ClientHelloSpec) error {
	return q.conn.ApplyPreset(p)
}

// NextEvent returns the next event occurring on the connection.
// It returns an event with a Kind of QUICNoEvent when no events are available.
func (q *UQUICConn) NextEvent() QUICEvent {
	qs := q.conn.quic
	if last := qs.nextEvent - 1; last >= 0 && len(qs.events[last].Data) > 0 {
		// Write over some of the previous event's data,
		// to catch callers erroniously retaining it.
		qs.events[last].Data[0] = 0
	}
	if qs.nextEvent >= len(qs.events) {
		qs.events = qs.events[:0]
		qs.nextEvent = 0
		return QUICEvent{Kind: QUICNoEvent}
	}
	e := qs.events[qs.nextEvent]
	qs.events[qs.nextEvent] = QUICEvent{} // zero out references to data
	qs.nextEvent++
	return e
}

// Close closes the connection and stops any in-progress handshake.
func (q *UQUICConn) Close() error {
	if q.conn.quic.cancel == nil {
		return nil // never started
	}
	q.conn.quic.cancel()
	for range q.conn.quic.blockedc {
		// Wait for the handshake goroutine to return.
	}
	return q.conn.handshakeErr
}

// HandleData handles handshake bytes received from the peer.
// It may produce connection events, which may be read with NextEvent.
func (q *UQUICConn) HandleData(level QUICEncryptionLevel, data []byte) error {
	c := q.conn
	if c.in.level != level {
		return quicError(c.in.setErrorLocked(errors.New("tls: handshake data received at wrong level")))
	}
	c.quic.readbuf = data
	<-c.quic.signalc
	_, ok := <-c.quic.blockedc
	if ok {
		// The handshake goroutine is waiting for more data.
		return nil
	}
	// The handshake goroutine has exited.
	c.hand.Write(c.quic.readbuf)
	c.quic.readbuf = nil
	for q.conn.hand.Len() >= 4 && q.conn.handshakeErr == nil {
		b := q.conn.hand.Bytes()
		n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		if 4+n < len(b) {
			return nil
		}
		if err := q.conn.handlePostHandshakeMessage(); err != nil {
			return quicError(err)
		}
	}
	if q.conn.handshakeErr != nil {
		return quicError(q.conn.handshakeErr)
	}
	return nil
}

// SendSessionTicket sends a session ticket to the client.
// It produces connection events, which may be read with NextEvent.
// Currently, it can only be called once.
func (q *UQUICConn) SendSessionTicket(opts QUICSessionTicketOptions) error {
	c := q.conn
	if !c.isHandshakeComplete.Load() {
		return quicError(errors.New("tls: SendSessionTicket called before handshake completed"))
	}
	if c.isClient {
		return quicError(errors.New("tls: SendSessionTicket called on the client"))
	}
	if q.sessionTicketSent {
		return quicError(errors.New("tls: SendSessionTicket called multiple times"))
	}
	q.sessionTicketSent = true
	return quicError(c.sendSessionTicket(opts.EarlyData))
}

// ConnectionState returns basic TLS details about the connection.
func (q *UQUICConn) ConnectionState() ConnectionState {
	return q.conn.ConnectionState()
}

// SetTransportParameters sets the transport parameters to send to the peer.
//
// Server connections may delay setting the transport parameters until after
// receiving the client's transport parameters. See QUICTransportParametersRequired.
func (q *UQUICConn) SetTransportParameters(params []byte) {
	if params == nil {
		params = []byte{}
	}
	q.conn.quic.transportParams = params // this won't be used for building ClientHello when using a preset

	// // instead, we set the transport parameters hold by the ClientHello
	// for _, ext := range q.conn.Extensions {
	// 	if qtp, ok := ext.(*QUICTransportParametersExtension); ok {
	// 		qtp.TransportParametersExtData = params
	// 	}
	// }

	if q.conn.quic.started {
		<-q.conn.quic.signalc
		<-q.conn.quic.blockedc
	}
}

func (uc *UConn) QUICSetReadSecret(level QUICEncryptionLevel, suite uint16, secret []byte) {
	uc.quic.events = append(uc.quic.events, QUICEvent{
		Kind:  QUICSetReadSecret,
		Level: level,
		Suite: suite,
		Data:  secret,
	})
}

func (uc *UConn) QUICSetWriteSecret(level QUICEncryptionLevel, suite uint16, secret []byte) {
	uc.quic.events = append(uc.quic.events, QUICEvent{
		Kind:  QUICSetWriteSecret,
		Level: level,
		Suite: suite,
		Data:  secret,
	})
}

func (uc *UConn) QUICGetTransportParameters() ([]byte, error) {
	if uc.quic.transportParams == nil {
		uc.quic.events = append(uc.quic.events, QUICEvent{
			Kind: QUICTransportParametersRequired,
		})
	}
	for uc.quic.transportParams == nil {
		if err := uc.quicWaitForSignal(); err != nil {
			return nil, err
		}
	}
	return uc.quic.transportParams, nil
}
