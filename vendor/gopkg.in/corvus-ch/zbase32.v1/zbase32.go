// Package zbase32 implements the z-base-32 encoding as specified in
// http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
//
// Note that this is NOT RFC 4648, for that see encoding/base32.
// z-base-32 is a variant that aims to be more human-friendly, and in
// some circumstances shorter.
//
// Bits
//
// When the amount of input is not a full number of bytes, encoding
// the data can lead to an unnecessary, non-information-carrying,
// trailing character in the encoded data. This package provides
// 'Bits' variants of the functions that can avoid outputting this
// unnecessary trailing character. For example, encoding a 20-bit
// message:
//
//     StdEncoding.EncodeToString([]byte{0x10, 0x11, 0x10}) == "nyety"
//     StdEncoding.EncodeBitsToString([]byte{0x10, 0x11, 0x10}, 20) == "nyet"
//
// Decoding such a message requires also using the 'Bits' variant
// function.
package zbase32

import (
	"errors"
	"io"
	"strconv"
)

/*
 * Encodings
 */

// An Encoding is a radix 32 encoding/decoding scheme, defined by a
// 32-character alphabet.
type Encoding struct {
	encoder   string
	decodeMap [256]byte
}

const encodeStd = "ybndrfg8ejkmcpqxot1uwisza345h769"

// NewEncoding returns a new Encoding defined by the given alphabet, which must
// be a 32-byte string.
//
// Note that this is NOT RFC 4648, for that see encoding/base32. z-base-32 is a
// variant that aims to be more human-friendly, and in some circumstances
// shorter.
func NewEncoding(encoder string) *Encoding {
	e := new(Encoding)
	e.encoder = encoder

	for i := 0; i < len(e.decodeMap); i++ {
		e.decodeMap[i] = 0xFF
	}
	for i := 0; i < len(encoder); i++ {
		e.decodeMap[encoder[i]] = byte(i)
	}
	return e
}

// StdEncoding is the standard z-base-32 encoding, using an alphabet as defined
// in http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt.
var StdEncoding = NewEncoding(encodeStd)

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}

/**
 * Encoder
 */

func (enc *Encoding) encode(dst, src []byte, bits int) int {
	off := 0
	for i := 0; i < bits || (bits < 0 && len(src) > 0); i += 5 {
		b0 := src[0]
		b1 := byte(0)

		if len(src) > 1 {
			b1 = src[1]
		}

		char := byte(0)
		offset := uint(i % 8)

		if offset < 4 {
			char = b0 & (31 << (3 - offset)) >> (3 - offset)
		} else {
			char = b0 & (31 >> (offset - 3)) << (offset - 3)
			char |= b1 & (255 << (11 - offset)) >> (11 - offset)
		}

		// If src is longer than necessary, mask trailing bits to zero
		if bits >= 0 && i+5 > bits {
			char &= 255 << uint((i+5)-bits)
		}

		dst[off] = enc.encoder[char]
		off++

		if offset > 2 {
			src = src[1:]
		}
	}
	return off
}

// EncodeBits encodes the specified number of bits of src. It writes at
// most EncodedLen(len(src)) bytes to dst and returns the number of
// bytes written.
//
// EncodeBits is not appropriate for use on individual blocks of a
// large data stream.
func (enc *Encoding) EncodeBits(dst, src []byte, bits int) int {
	if bits < 0 {
		return 0
	}
	return enc.encode(dst, src, bits)
}

// Encode encodes src using the encoding enc, writing EncodedLen(len(src))
// bytes to dst.
//
// The encoding is not appropriate for use on individual blocks of a large data
// stream. Use NewEncoder() instead.
func (enc *Encoding) Encode(dst, src []byte) int {
	return enc.encode(dst, src, -1)
}

// EncodeToString returns the z-base-32 encoding of src.
func (enc *Encoding) EncodeToString(src []byte) string {
	buf := make([]byte, enc.EncodedLen(len(src)))
	n := enc.Encode(buf, src)
	return string(buf[:n])
}

// EncodeBitsToString returns the z-base-32 encoding of the specified
// number of bits of src.
func (enc *Encoding) EncodeBitsToString(src []byte, bits int) string {
	dst := make([]byte, enc.EncodedLen(len(src)))
	n := enc.EncodeBits(dst, src, bits)
	return string(dst[:n])
}

type encoder struct {
	io.WriteCloser
	enc  *Encoding
	w    io.Writer
	buf  [5]byte    // buffered data waiting to be encoded
	nbuf int        // number of bytes in buf
	out  [1024]byte // output buffer
	err  error
}

func (e *encoder) Write(p []byte) (n int, err error) {
	if e.err != nil {
		return 0, e.err
	}

	// Leading fringe.
	if e.nbuf > 0 {
		var i int
		for i = 0; i < len(p) && e.nbuf < 5; i++ {
			e.buf[e.nbuf] = p[i]
			e.nbuf++
		}
		n += i
		p = p[i:]
		if e.nbuf < 5 {
			return
		}
		m := e.enc.Encode(e.out[0:], e.buf[0:])
		if _, e.err = e.w.Write(e.out[0:m]); e.err != nil {
			return n, e.err
		}
		e.nbuf = 0
	}

	// Large interior chunks.
	for len(p) >= 5 {
		nn := len(e.out) / 8 * 5
		if nn > len(p) {
			nn = len(p)
			nn -= nn % 5
		}
		m := e.enc.Encode(e.out[0:], p[0:nn])
		if _, e.err = e.w.Write(e.out[0:m]); e.err != nil {
			return n, e.err
		}
		n += nn
		p = p[nn:]
	}

	// Trailing fringe.
	for i := 0; i < len(p); i++ {
		e.buf[i] = p[i]
	}
	e.nbuf = len(p)
	n += len(p)
	return
}

// Close flushes any pending output from the encoder. It is an error to call
// Write after calling Close.
func (e *encoder) Close() error {
	// If there's anything left in the buffer, flush it out
	if e.err == nil && e.nbuf > 0 {
		m := e.enc.Encode(e.out[0:], e.buf[0:e.nbuf])
		_, e.err = e.w.Write(e.out[0:m])
		e.nbuf = 0
	}
	return e.err
}

// NewEncoder returns a new z-base-32 stream encoder. Data written to the
// returned writer will be encoded using enc and then written to r. z-Base-32
// encodings operate in 5-byte blocks; when finished writing, the caller must
// Close the returned encoder to flush any partially written blocks.
func NewEncoder(enc *Encoding, w io.Writer) io.WriteCloser {
	return &encoder{enc: enc, w: w}
}

// EncodedLen returns the length in bytes of the z-base-32 encoding of an input
// buffer of length n.
func (enc *Encoding) EncodedLen(n int) int {
	return (n + 4) / 5 * 8
}

/*
 * Decoder
 */

// CorruptInputError means that the byte at this offset was not a valid
// z-base-32 encoding byte.
type CorruptInputError int64

func (e CorruptInputError) Error() string {
	return "illegal z-base-32 data at input byte " + strconv.FormatInt(int64(e), 10)
}

func (enc *Encoding) decode(dst, src []byte, bits int) (int, error) {
	olen := len(src)
	off := 0
	for len(src) > 0 {
		// Decode quantum using the z-base-32 alphabet
		var dbuf [8]byte

		j := 0
		for ; j < 8; j++ {
			if len(src) == 0 {
				break
			}
			in := src[0]
			src = src[1:]
			dbuf[j] = enc.decodeMap[in]
			if dbuf[j] == 0xFF {
				return off, CorruptInputError(olen - len(src) - 1)
			}
		}

		// 8x 5-bit source blocks, 5 byte destination quantum
		dst[off+0] = dbuf[0]<<3 | dbuf[1]>>2
		dst[off+1] = dbuf[1]<<6 | dbuf[2]<<1 | dbuf[3]>>4
		dst[off+2] = dbuf[3]<<4 | dbuf[4]>>1
		dst[off+3] = dbuf[4]<<7 | dbuf[5]<<2 | dbuf[6]>>3
		dst[off+4] = dbuf[6]<<5 | dbuf[7]

		// bits < 0 means as many bits as there are in src
		if bits < 0 {
			var lookup = []int{0, 1, 1, 2, 2, 3, 4, 4, 5}
			off += lookup[j]
			continue
		}
		bitsInBlock := bits
		if bitsInBlock > 40 {
			bitsInBlock = 40
		}
		off += (bitsInBlock + 7) / 8
		bits -= 40
	}
	return off, nil
}

// DecodeBits decodes the specified number of bits of z-base-32
// encoded data from src. It writes at most DecodedLen(len(src)) bytes
// to dst and returns the number of bytes written.
//
// If src contains invalid z-base-32 data, it will return the number
// of bytes successfully written and CorruptInputError.
func (enc *Encoding) DecodeBits(dst, src []byte, bits int) (int, error) {
	if bits < 0 {
		return 0, errors.New("cannot decode a negative bit count")
	}
	return enc.decode(dst, src, bits)
}

// Decode decodes src using the encoding enc. It writes at most
// DecodedLen(len(src)) bytes to dst and returns the number of bytes written.
// If src contains invalid z-base-32 data, it will return the number of bytes
// successfully written and CorruptInputError.
func (enc *Encoding) Decode(dst, src []byte) (int, error) {
	return enc.decode(dst, src, -1)
}

func (enc *Encoding) decodeString(s string, bits int) ([]byte, error) {
	dst := make([]byte, enc.DecodedLen(len(s)))
	n, err := enc.decode(dst, []byte(s), bits)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// DecodeBitsString returns the bytes represented by the z-base-32
// string s containing the specified number of bits.
func (enc *Encoding) DecodeBitsString(s string, bits int) ([]byte, error) {
	if bits < 0 {
		return nil, errors.New("cannot decode a negative bit count")

	}

	return enc.decodeString(s, bits)
}

// DecodeString returns the z-base-32 decoded bytes of string s.
func (enc *Encoding) DecodeString(s string) ([]byte, error) {
	return enc.decodeString(s, -1)
}

// DecodedLen returns the maximum length in bytes of the decoded data
// corresponding to n bytes of z-base-32-encoded data.
func (enc *Encoding) DecodedLen(n int) int {
	return (n + 7) / 8 * 5
}

type decoder struct {
	io.Reader
	enc  *Encoding
	r    io.Reader
	buf  [1024]byte // buffered data waiting to read.
	nbuf int        // the number of bytes in buf
	eof  bool       // indicates that the underlying reader has reached EOF
	err  error
}

func (d *decoder) Read(p []byte) (int, error) {
	var n int

	if d.nbuf < 1 && !d.eof {
		buf := make([]byte, 640)
		l, err := d.r.Read(buf)
		if io.EOF == err {
			d.eof = true
		} else if nil != err {
			return n, err
		}
		if d.nbuf, err = d.enc.Decode(d.buf[0:], buf[:l]); nil != err {
			return n, err
		}
	}

	for n < len(p) && d.nbuf > 0 {
		m := copy(p[n:], d.buf[:(min(d.nbuf, len(p)))])
		d.nbuf -= m
		for i := 0; i < d.nbuf; i++ {
			d.buf[i] = d.buf[i+m]
		}
		n += m
	}

	if d.eof == true && d.nbuf == 0 {
		return n, io.EOF
	}

	return n, nil
}

// NewDecoder returns a new z-base-32 stream decoder. Data read from the
// returned reader will be read from r and then decoded using enc.
func NewDecoder(enc *Encoding, r io.Reader) io.Reader {
	return &decoder{enc: enc, r: r}
}
