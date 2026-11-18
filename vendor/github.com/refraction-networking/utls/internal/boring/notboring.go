package boring

import (
	"crypto/cipher"
	"errors"
)

const Enabled bool = false

func NewGCMTLS(_ cipher.Block) (cipher.AEAD, error) {
	return nil, errors.New("boring not implemented")
}

func NewGCMTLS13(_ cipher.Block) (cipher.AEAD, error) {
	return nil, errors.New("boring not implemented")
}

func Unreachable() {
	// do nothing
}
