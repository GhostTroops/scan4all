package helper

import (
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

// Uint8to16 converts a slice of uint8 to a slice of uint16.
// e.g. []uint8{0x00, 0x01, 0x00, 0x02} -> []uint16{0x0001, 0x0002}
func Uint8to16(in []uint8) ([]uint16, error) {
	s := cryptobyte.String(in)
	var out []uint16
	for !s.Empty() {
		var v uint16
		if s.ReadUint16(&v) {
			out = append(out, v)
		} else {
			return nil, errors.New("ReadUint16 failed")
		}
	}
	return out, nil
}
