// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtp

import (
	"encoding/binary"
	"errors"
)

const (
	playoutDelayExtensionSize = 3
	playoutDelayMaxValue      = (1 << 12) - 1
)

var errPlayoutDelayInvalidValue = errors.New("invalid playout delay value")

// PlayoutDelayExtension is a extension payload format in
// http://www.webrtc.org/experiments/rtp-hdrext/playout-delay
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  ID   | len=2 |       MIN delay       |       MAX delay       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type PlayoutDelayExtension struct {
	minDelay, maxDelay uint16
}

// Marshal serializes the members to buffer
func (p PlayoutDelayExtension) Marshal() ([]byte, error) {
	if p.minDelay > playoutDelayMaxValue || p.maxDelay > playoutDelayMaxValue {
		return nil, errPlayoutDelayInvalidValue
	}

	return []byte{
		byte(p.minDelay >> 4),
		byte(p.minDelay<<4) | byte(p.maxDelay>>8),
		byte(p.maxDelay),
	}, nil
}

// Unmarshal parses the passed byte slice and stores the result in the members
func (p *PlayoutDelayExtension) Unmarshal(rawData []byte) error {
	if len(rawData) < playoutDelayExtensionSize {
		return errTooSmall
	}
	p.minDelay = binary.BigEndian.Uint16(rawData[0:2]) >> 4
	p.maxDelay = binary.BigEndian.Uint16(rawData[1:3]) & 0x0FFF
	return nil
}
