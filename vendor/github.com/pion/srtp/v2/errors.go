// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"errors"
	"fmt"
)

var (
	errDuplicated                    = errors.New("duplicated packet")
	errShortSrtpMasterKey            = errors.New("SRTP master key is not long enough")
	errShortSrtpMasterSalt           = errors.New("SRTP master salt is not long enough")
	errNoSuchSRTPProfile             = errors.New("no such SRTP Profile")
	errNonZeroKDRNotSupported        = errors.New("indexOverKdr > 0 is not supported yet")
	errExporterWrongLabel            = errors.New("exporter called with wrong label")
	errNoConfig                      = errors.New("no config provided")
	errNoConn                        = errors.New("no conn provided")
	errFailedToVerifyAuthTag         = errors.New("failed to verify auth tag")
	errTooShortRTCP                  = errors.New("packet is too short to be rtcp packet")
	errPayloadDiffers                = errors.New("payload differs")
	errStartedChannelUsedIncorrectly = errors.New("started channel used incorrectly, should only be closed")
	errBadIVLength                   = errors.New("bad iv length in xorBytesCTR")
	errExceededMaxPackets            = errors.New("exceeded the maximum number of packets")

	errStreamNotInited     = errors.New("stream has not been inited, unable to close")
	errStreamAlreadyClosed = errors.New("stream is already closed")
	errStreamAlreadyInited = errors.New("stream is already inited")
	errFailedTypeAssertion = errors.New("failed to cast child")
)

type duplicatedError struct {
	Proto string // srtp or srtcp
	SSRC  uint32
	Index uint32 // sequence number or index
}

func (e *duplicatedError) Error() string {
	return fmt.Sprintf("%s ssrc=%d index=%d: %v", e.Proto, e.SSRC, e.Index, errDuplicated)
}

func (e *duplicatedError) Unwrap() error {
	return errDuplicated
}
