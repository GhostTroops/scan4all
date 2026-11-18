package giop

import (
	"encoding/binary"
	"encoding/hex"
)

func D(str string) []byte {
	data, _ := hex.DecodeString(str)
	return data
}

func E(b []byte) string {
	return hex.EncodeToString(b)
}

func Int32(i int) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(i))
	return b
}
