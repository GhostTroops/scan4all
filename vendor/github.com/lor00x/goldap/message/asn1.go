package message

// Below code is largely inspired from the standard golang library encoding/asn
// If put BEGIN / END tags in the comments to give the original library name
import (
	//	"errors"
	"fmt"
	"math/big"
	// "strconv"
	// "time"
)

//
// BEGIN: encoding/asn1/common.go
//

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
const (
	tagBoolean = 1
	tagInteger = 2
	// tagBitString   = 3
	tagOctetString = 4
	// tagOID         = 6
	tagEnum = 10
	// tagUTF8String = 12
	tagSequence = 16
	tagSet      = 17
	// tagPrintableString = 19
	// tagT61String       = 20
	// tagIA5String       = 22
	// tagUTCTime         = 23
	// tagGeneralizedTime = 24
	tagGeneralString = 27
)

var tagNames = map[int]string{
	tagBoolean:     "BOOLEAN",
	tagInteger:     "INTEGER",
	tagOctetString: "OCTET STRING",
	tagEnum:        "ENUM",
	tagSequence: "SEQUENCE",
	tagSet:      "SET",
}

const (
	classUniversal       = 0
	classApplication     = 1
	classContextSpecific = 2
	// classPrivate         = 3
)

var classNames = map[int]string{
	classUniversal:       "UNIVERSAL",
	classApplication:     "APPLICATION",
	classContextSpecific: "CONTEXT SPECIFIC",
}

const (
	isCompound    = true
	isNotCompound = false
)

var compoundNames = map[bool]string{
	isCompound:    "COMPOUND",
	isNotCompound: "NOT COMPOUND",
}

type TagAndLength struct {
	Class, Tag, Length int
	IsCompound         bool
}

//
// END: encoding/asn1/common.go
//

func (t *TagAndLength) Expect(class int, tag int, isCompound bool) (err error) {
	err = t.ExpectClass(class)
	if err != nil {
		return LdapError{fmt.Sprintf("Expect: %s.", err)}
	}
	err = t.ExpectTag(tag)
	if err != nil {
		return LdapError{fmt.Sprintf("Expect: %s.", err)}
	}
	err = t.ExpectCompound(isCompound)
	if err != nil {
		return LdapError{fmt.Sprintf("Expect: %s.", err)}
	}
	return
}
func (t *TagAndLength) ExpectClass(class int) (err error) {
	if class != t.Class {
		err = SyntaxError{fmt.Sprintf("ExpectClass: wrong tag class: got %d (%s), expected %d (%s)", t.Class, classNames[t.Class], class, classNames[class])}
	}
	return
}
func (t *TagAndLength) ExpectTag(tag int) (err error) {
	if tag != t.Tag {
		err = SyntaxError{fmt.Sprintf("ExpectTag: wrong tag value: got %d (%s), expected %d (%s)", t.Tag, tagNames[t.Tag], tag, tagNames[tag])}
	}
	return
}
func (t *TagAndLength) ExpectCompound(isCompound bool) (err error) {
	if isCompound != t.IsCompound {
		err = SyntaxError{fmt.Sprintf("ExpectCompound: wrong tag compound: got %t (%s), expected %t (%s)", t.IsCompound, compoundNames[t.IsCompound], isCompound, compoundNames[isCompound])}
	}
	return
}

func ParseTagAndLength(bytes []byte, initOffset int) (ret TagAndLength, offset int, err error) {
	ret, offset, err = parseTagAndLength(bytes, initOffset)
	return
}

//
// BEGIN encoding/asn1/asn1.go
//

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package asn1 implements parsing of DER-encoded ASN.1 data structures,
// as defined in ITU-T Rec X.690.
//
// See also ``A Layman's Guide to a Subset of ASN.1, BER, and DER,''
// http://luca.ntop.org/Teaching/Appunti/asn1.html.
// package asn1

// ASN.1 is a syntax for specifying abstract objects and BER, DER, PER, XER etc
// are different encoding formats for those objects. Here, we'll be dealing
// with DER, the Distinguished Encoding Rules. DER is used in X.509 because
// it's fast to parse and, unlike BER, has a unique encoding for every object.
// When calculating hashes over objects, it's important that the resulting
// bytes be the same at both ends and DER removes this margin of error.
//
// ASN.1 is very complex and this package doesn't attempt to implement
// everything by any means.

//import (
//	"fmt"
//	"math/big"
//	"reflect"
//	"strconv"
//	"time"
//)

// A StructuralError suggests that the ASN.1 data is valid, but the Go type
// which is receiving it doesn't match.
type StructuralError struct {
	Msg string
}

func (e StructuralError) Error() string { return "asn1: structure error: " + e.Msg }

// A SyntaxError suggests that the ASN.1 data is invalid.
type SyntaxError struct {
	Msg string
}

func (e SyntaxError) Error() string { return "asn1: syntax error: " + e.Msg }

// We start by dealing with each of the primitive types in turn.

// BOOLEAN

func parseBool(bytes []byte) (ret bool, err error) {
	if len(bytes) > 1 {
		err = SyntaxError{"invalid boolean: should be encoded on one byte only"}
		return
	} else if len(bytes) == 0 {
		err = SyntaxError{"invalid boolean: no data to read"}
	}

	// DER demands that "If the encoding represents the boolean value TRUE,
	// its single contents octet shall have all eight bits set to one."
	// Thus only 0 and 255 are valid encoded values.
	switch bytes[0] {
	case 0:
		ret = false
	case 0xff:
		ret = true
	default:
		err = SyntaxError{"invalid boolean: should be 0x00 of 0xFF"}
	}

	return
}

func sizeBool(b bool) int {
	return 1
}

func writeBool(bytes *Bytes, b bool) int {
	if b == false {
		return bytes.writeBytes([]byte{0x00})
	} else {
		return bytes.writeBytes([]byte{0xff})
	}
}

// INTEGER

// parseInt64 treats the given bytes as a big-endian, signed integer and
// returns the result.
func parseInt64(bytes []byte) (ret int64, err error) {
	if len(bytes) > 8 {
		// We'll overflow an int64 in this case.
		err = StructuralError{"integer too large"}
		return
	}
	for bytesRead := 0; bytesRead < len(bytes); bytesRead++ {
		ret <<= 8
		ret |= int64(bytes[bytesRead])
	}

	// Shift up and down in order to sign extend the result.
	ret <<= 64 - uint8(len(bytes))*8
	ret >>= 64 - uint8(len(bytes))*8
	return
}

func sizeInt64(i int64) (size int) {
	for ; i != 0 || size == 0; i >>= 8 {
		size++
	}
	return
}

func writeInt64(bytes *Bytes, i int64) (size int) {
	for ; i != 0 || size == 0; i >>= 8 { // Write at least one byte even if the value is 0
		bytes.writeBytes([]byte{byte(i)})
		size++
	}
	return
}

// parseInt treats the given bytes as a big-endian, signed integer and returns
// the result.
func parseInt32(bytes []byte) (int32, error) {
	ret64, err := parseInt64(bytes)
	if err != nil {
		return 0, err
	}
	if ret64 != int64(int32(ret64)) {
		return 0, StructuralError{"integer too large"}
	}
	return int32(ret64), nil
}

func sizeInt32(i int32) int {
	return sizeInt64(int64(i))
}

func writeInt32(bytes *Bytes, i int32) int {
	return writeInt64(bytes, int64(i))
}

var bigOne = big.NewInt(1)

// // parseBigInt treats the given bytes as a big-endian, signed integer and returns
// // the result.
// func parseBigInt(bytes []byte) *big.Int {
// 	ret := new(big.Int)
// 	if len(bytes) > 0 && bytes[0]&0x80 == 0x80 {
// 		// This is a negative number.
// 		notBytes := make([]byte, len(bytes))
// 		for i := range notBytes {
// 			notBytes[i] = ^bytes[i]
// 		}
// 		ret.SetBytes(notBytes)
// 		ret.Add(ret, bigOne)
// 		ret.Neg(ret)
// 		return ret
// 	}
// 	ret.SetBytes(bytes)
// 	return ret
// }

// // BIT STRING

// // BitString is the structure to use when you want an ASN.1 BIT STRING type. A
// // bit string is padded up to the nearest byte in memory and the number of
// // valid bits is recorded. Padding bits will be zero.
// type BitString struct {
// 	Bytes     []byte // bits packed into bytes.
// 	BitLength int    // length in bits.
// }

// // At returns the bit at the given index. If the index is out of range it
// // returns false.
// func (b BitString) At(i int) int {
// 	if i < 0 || i >= b.BitLength {
// 		return 0
// 	}
// 	x := i / 8
// 	y := 7 - uint(i%8)
// 	return int(b.Bytes[x]>>y) & 1
// }

// // RightAlign returns a slice where the padding bits are at the beginning. The
// // slice may share memory with the BitString.
// func (b BitString) RightAlign() []byte {
// 	shift := uint(8 - (b.BitLength % 8))
// 	if shift == 8 || len(b.Bytes) == 0 {
// 		return b.Bytes
// 	}

// 	a := make([]byte, len(b.Bytes))
// 	a[0] = b.Bytes[0] >> shift
// 	for i := 1; i < len(b.Bytes); i++ {
// 		a[i] = b.Bytes[i-1] << (8 - shift)
// 		a[i] |= b.Bytes[i] >> shift
// 	}

// 	return a
// }

// // parseBitString parses an ASN.1 bit string from the given byte slice and returns it.
// func parseBitString(bytes []byte) (ret BitString, err error) {
// 	if len(bytes) == 0 {
// 		err = SyntaxError{"zero length BIT STRING"}
// 		return
// 	}
// 	paddingBits := int(bytes[0])
// 	if paddingBits > 7 ||
// 		len(bytes) == 1 && paddingBits > 0 ||
// 		bytes[len(bytes)-1]&((1<<bytes[0])-1) != 0 {
// 		err = SyntaxError{"invalid padding bits in BIT STRING"}
// 		return
// 	}
// 	ret.BitLength = (len(bytes)-1)*8 - paddingBits
// 	ret.Bytes = bytes[1:]
// 	return
// }

// OBJECT IDENTIFIER

// An ObjectIdentifier represents an ASN.1 OBJECT IDENTIFIER.
// type ObjectIdentifier []int

// // Equal reports whether oi and other represent the same identifier.
// func (oi ObjectIdentifier) Equal(other ObjectIdentifier) bool {
// 	if len(oi) != len(other) {
// 		return false
// 	}
// 	for i := 0; i < len(oi); i++ {
// 		if oi[i] != other[i] {
// 			return false
// 		}
// 	}

// 	return true
// }

// func (oi ObjectIdentifier) String() string {
// 	var s string

// 	for i, v := range oi {
// 		if i > 0 {
// 			s += "."
// 		}
// 		s += strconv.Itoa(v)
// 	}

// 	return s
// }

// // parseObjectIdentifier parses an OBJECT IDENTIFIER from the given bytes and
// // returns it. An object identifier is a sequence of variable length integers
// // that are assigned in a hierarchy.
// func parseObjectIdentifier(bytes []byte) (s []int, err error) {
// 	if len(bytes) == 0 {
// 		err = SyntaxError{"zero length OBJECT IDENTIFIER"}
// 		return
// 	}

// 	// In the worst case, we get two elements from the first byte (which is
// 	// encoded differently) and then every varint is a single byte long.
// 	s = make([]int, len(bytes)+1)

// 	// The first varint is 40*value1 + value2:
// 	// According to this packing, value1 can take the values 0, 1 and 2 only.
// 	// When value1 = 0 or value1 = 1, then value2 is <= 39. When value1 = 2,
// 	// then there are no restrictions on value2.
// 	v, offset, err := parseBase128Int(bytes, 0)
// 	if err != nil {
// 		return
// 	}
// 	if v < 80 {
// 		s[0] = v / 40
// 		s[1] = v % 40
// 	} else {
// 		s[0] = 2
// 		s[1] = v - 80
// 	}

// 	i := 2
// 	for ; offset < len(bytes); i++ {
// 		v, offset, err = parseBase128Int(bytes, offset)
// 		if err != nil {
// 			return
// 		}
// 		s[i] = v
// 	}
// 	s = s[0:i]
// 	return
// }

// ENUMERATED

// An Enumerated is represented as a plain int.
type Enumerated int

// FLAG

// A Flag accepts any data and is set to true if present.
type Flag bool

// parseBase128Int parses a base-128 encoded int from the given offset in the
// given byte slice. It returns the value and the new offset.
func parseBase128Int(bytes []byte, initOffset int) (ret, offset int, err error) {
	offset = initOffset
	for shifted := 0; offset < len(bytes); shifted++ {
		if shifted > 4 {
			err = StructuralError{"base 128 integer too large"}
			return
		}
		ret <<= 7
		b := bytes[offset]
		ret |= int(b & 0x7f)
		offset++
		if b&0x80 == 0 {
			return
		}
	}
	err = SyntaxError{"truncated base 128 integer"}
	return
}

func sizeBase128Int(value int) (size int) {
	for i := value; i > 0; i >>= 7 {
		size++
	}
	return
}

// Write start as the end of the slice and goes back
// We assume we have enough size
func writeBase128Int(bytes *Bytes, value int) (size int) {
	for ; value > 0 || size == 0; value >>= 7 { // Write at least one byte even if the value is 0
		// Get the 7 lowest bits
		b := byte(value) & 0x7f
		if value < 128 {
			b |= 0x80
		}
		bytes.writeBytes([]byte{b})
		size++
	}
	return
}

// // UTCTime

// func parseUTCTime(bytes []byte) (ret time.Time, err error) {
// 	s := string(bytes)
// 	ret, err = time.Parse("0601021504Z0700", s)
// 	if err != nil {
// 		ret, err = time.Parse("060102150405Z0700", s)
// 	}
// 	if err == nil && ret.Year() >= 2050 {
// 		// UTCTime only encodes times prior to 2050. See https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
// 		ret = ret.AddDate(-100, 0, 0)
// 	}

// 	return
// }

// // parseGeneralizedTime parses the GeneralizedTime from the given byte slice
// // and returns the resulting time.
// func parseGeneralizedTime(bytes []byte) (ret time.Time, err error) {
// 	return time.Parse("20060102150405Z0700", string(bytes))
// }

// // PrintableString

// // parsePrintableString parses a ASN.1 PrintableString from the given byte
// // array and returns it.
// func parsePrintableString(bytes []byte) (ret string, err error) {
// 	for _, b := range bytes {
// 		if !isPrintable(b) {
// 			err = SyntaxError{"PrintableString contains invalid character"}
// 			return
// 		}
// 	}
// 	ret = string(bytes)
// 	return
// }

// // isPrintable returns true iff the given b is in the ASN.1 PrintableString set.
// func isPrintable(b byte) bool {
// 	return 'a' <= b && b <= 'z' ||
// 		'A' <= b && b <= 'Z' ||
// 		'0' <= b && b <= '9' ||
// 		'\'' <= b && b <= ')' ||
// 		'+' <= b && b <= '/' ||
// 		b == ' ' ||
// 		b == ':' ||
// 		b == '=' ||
// 		b == '?' ||
// 		// This is technically not allowed in a PrintableString.
// 		// However, x509 certificates with wildcard strings don't
// 		// always use the correct string type so we permit it.
// 		b == '*'
// }

// // IA5String

// // parseIA5String parses a ASN.1 IA5String (ASCII string) from the given
// // byte slice and returns it.
// func parseIA5String(bytes []byte) (ret string, err error) {
// 	for _, b := range bytes {
// 		if b >= 0x80 {
// 			err = SyntaxError{"IA5String contains invalid character"}
// 			return
// 		}
// 	}
// 	ret = string(bytes)
// 	return
// }

// // T61String

// // parseT61String parses a ASN.1 T61String (8-bit clean string) from the given
// // byte slice and returns it.
// func parseT61String(bytes []byte) (ret string, err error) {
// 	return string(bytes), nil
// }

// UTF8String

// parseUTF8String parses a ASN.1 UTF8String (raw UTF-8) from the given byte
// array and returns it.
// func parseUTF8String(bytes []byte) (ret string, err error) {
// 	return string(bytes), nil
// }
// func sizeUTF8String(s string) int {
// 	return len(s)
// }
// func writeUTF8String(bytes *Bytes, s string) int {
// 	return bytes.writeString(s)
// }

// Octet string
func parseOctetString(bytes []byte) (ret []byte, err error) {
	return bytes, nil
}
func sizeOctetString(s []byte) int {
	return len(s)
}
func writeOctetString(bytes *Bytes, s []byte) int {
	return bytes.writeBytes(s)
}

// A RawValue represents an undecoded ASN.1 object.
type RawValue struct {
	Class, Tag int
	IsCompound bool
	Bytes      []byte
	FullBytes  []byte // includes the tag and length
}

// RawContent is used to signal that the undecoded, DER data needs to be
// preserved for a struct. To use it, the first field of the struct must have
// this type. It's an error for any of the other fields to have this type.
type RawContent []byte

// Tagging

// parseTagAndLength parses an ASN.1 tag and length pair from the given offset
// into a byte slice. It returns the parsed data and the new offset. SET and
// SET OF (tag 17) are mapped to SEQUENCE and SEQUENCE OF (tag 16) since we
// don't distinguish between ordered and unordered objects in this code.
func parseTagAndLength(bytes []byte, initOffset int) (ret TagAndLength, offset int, err error) {
	offset = initOffset
	b := bytes[offset]
	offset++
	ret.Class = int(b >> 6)
	ret.IsCompound = b&0x20 == 0x20
	ret.Tag = int(b & 0x1f)

	// If the bottom five bits are set, then the tag number is actually base 128
	// encoded afterwards
	if ret.Tag == 0x1f {
		ret.Tag, offset, err = parseBase128Int(bytes, offset)
		if err != nil {
			return
		}
	}
	if offset >= len(bytes) {
		err = SyntaxError{"truncated tag or length"}
		return
	}
	b = bytes[offset]
	offset++
	if b&0x80 == 0 {
		// The length is encoded in the bottom 7 bits.
		ret.Length = int(b & 0x7f)
	} else {
		// Bottom 7 bits give the number of length bytes to follow.
		numBytes := int(b & 0x7f)
		if numBytes == 0 {
			err = SyntaxError{"indefinite length found (not DER)"}
			return
		}
		ret.Length = 0
		for i := 0; i < numBytes; i++ {
			if offset >= len(bytes) {
				err = SyntaxError{"truncated tag or length"}
				return
			}
			b = bytes[offset]
			offset++
			if ret.Length >= 1<<23 {
				// We can't shift ret.length up without
				// overflowing.
				err = StructuralError{"length too large"}
				return
			}
			ret.Length <<= 8
			ret.Length |= int(b)
			if ret.Length == 0 {
				// DER requires that lengths be minimal.
				err = StructuralError{"superfluous leading zeros in length"}
				return
			}
		}
	}

	return
}

// func writeTagAndLength(out *forkableWriter, t tagAndLength) (err error) {
// 	b := uint8(t.class) << 6
// 	if t.isCompound {
// 		b |= 0x20
// 	}
// 	if t.tag >= 31 {
// 		b |= 0x1f
// 		err = out.WriteByte(b)
// 		if err != nil {
// 			return
// 		}
// 		err = marshalBase128Int(out, int64(t.tag))
// 		if err != nil {
// 			return
// 		}
// 	} else {
// 		b |= uint8(t.tag)
// 		err = out.WriteByte(b)
// 		if err != nil {
// 			return
// 		}
// 	}

// 	if t.length >= 128 {
// 		l := lengthLength(t.length)
// 		err = out.WriteByte(0x80 | byte(l))
// 		if err != nil {
// 			return
// 		}
// 		err = marshalLength(out, t.length)
// 		if err != nil {
// 			return
// 		}
// 	} else {
// 		err = out.WriteByte(byte(t.length))
// 		if err != nil {
// 			return
// 		}
// 	}

// 	return nil
// }

func sizeTagAndLength(tag int, length int) (size int) {
	// Compute the size of the tag
	size = 1
	if tag >= 31 {
		// Long-form identifier if the tag is greater than 30
		// http://en.wikipedia.org/wiki/X.690#Identifier_tags_greater_than_30
		size += sizeBase128Int(tag)
	}
	// Compute the size of the length using the definite form
	// http://en.wikipedia.org/wiki/X.690#The_definite_form
	size += 1
	if length >= 128 {
		size += 1
		for length > 255 {
			size++
			length >>= 8
		}
	}
	return
}

func writeTagAndLength(bytes *Bytes, t TagAndLength) (size int) {
	// We are writing backward, so write the length bytes first
	if t.Length < 0 {
		panic("Can't have a negative length")

	} else if t.Length >= 128 {
		lengthBytes := writeInt64(bytes, int64(t.Length))
		bytes.writeBytes([]byte{byte(0x80 | byte(lengthBytes))})
		size += lengthBytes + 1

	} else if t.Length < 128 {
		size += bytes.writeBytes([]byte{byte(t.Length)})
	}
	// Then write the tag
	b := uint8(t.Class) << 6
	if t.IsCompound {
		b |= 0x20
	}
	if t.Tag >= 31 {
		b |= 0x1f
		size += writeBase128Int(bytes, t.Tag)
	} else {
		b |= uint8(t.Tag)
	}
	size += bytes.writeBytes([]byte{byte(b)})
	return
}

//
// END encoding/asn1/asn1.go
//
