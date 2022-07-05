package message

import (
	"fmt"
)

type Bytes struct {
	offset int
	bytes  []byte
}

func (bytes *Bytes) getBytes() []byte {
	return bytes.bytes
}
func NewBytes(offset int, bytes []byte) (ret *Bytes) {
	return &Bytes{offset: offset, bytes: bytes}
}

func (bytes Bytes) Debug() {
	fmt.Printf("Offset: %d, Bytes: %+v\n", bytes.offset, bytes.bytes)
}

// Return a string with the hex dump of the bytes around the current offset
// The current offset byte is put in brackets
// Example: 0x01, [0x02], 0x03
func (bytes *Bytes) DumpCurrentBytes() (ret string) {
	var strings [3]string
	for i := -1; i <= 1; i++ {
		if bytes.offset+i >= 0 && bytes.offset+i < len(bytes.bytes) {
			strings[i+1] = fmt.Sprintf("%#x", bytes.bytes[bytes.offset+i])
		}
	}
	ret = fmt.Sprintf("%s, [%s], %s", strings[0], strings[1], strings[2])
	return
}

func (bytes *Bytes) HasMoreData() bool {
	return bytes.offset < len(bytes.bytes)
}

func (bytes *Bytes) ParseTagAndLength() (ret TagAndLength, err error) {
	var offset int
	ret, offset, err = ParseTagAndLength(bytes.bytes, bytes.offset)
	if err != nil {
		err = LdapError{fmt.Sprintf("ParseTagAndLength: %s", err.Error())}
		return
	} else {
		bytes.offset = offset
	}
	return
}

func (bytes *Bytes) ReadSubBytes(class int, tag int, callback func(bytes *Bytes) error) (err error) {
	// Check tag
	tagAndLength, err := bytes.ParseTagAndLength()
	if err != nil {
		return LdapError{fmt.Sprintf("ReadSubBytes:\n%s", err.Error())}
	}
	err = tagAndLength.Expect(class, tag, isCompound)
	if err != nil {
		return LdapError{fmt.Sprintf("ReadSubBytes:\n%s", err.Error())}
	}

	start := bytes.offset
	end := bytes.offset + tagAndLength.Length

	// Check we got enough bytes to process
	if end > len(bytes.bytes) {
		return LdapError{fmt.Sprintf("ReadSubBytes: data truncated: expecting %d bytes at offset %d", tagAndLength.Length, bytes.offset)}
	}
	// Process sub-bytes
	subBytes := Bytes{offset: 0, bytes: bytes.bytes[start:end]}
	err = callback(&subBytes)
	if err != nil {
		bytes.offset += subBytes.offset
		err = LdapError{fmt.Sprintf("ReadSubBytes:\n%s", err.Error())}
		return
	}
	// Check we got no more bytes to process
	if subBytes.HasMoreData() {
		return LdapError{fmt.Sprintf("ReadSubBytes: data too long: %d more bytes to read at offset %d", end-bytes.offset, bytes.offset)}
	}
	// Move offset
	bytes.offset = end
	return
}

func SizeSubBytes(tag int, callback func() int) (size int) {
	size = callback()
	size += sizeTagAndLength(tag, size)
	return
}

func (bytes *Bytes) WritePrimitiveSubBytes(class int, tag int, value interface{}) (size int) {
	switch value.(type) {
	case BOOLEAN:
		size = writeBool(bytes, bool(value.(BOOLEAN)))
	case INTEGER:
		size = writeInt32(bytes, int32(value.(INTEGER)))
	case ENUMERATED:
		size = writeInt32(bytes, int32(value.(ENUMERATED)))
	case OCTETSTRING:
		size = writeOctetString(bytes, []byte(string(value.(OCTETSTRING))))
	default:
		panic(fmt.Sprintf("WritePrimitiveSubBytes: invalid value type %v", value))
	}
	size += bytes.WriteTagAndLength(class, isNotCompound, tag, size)
	return
}

func (bytes *Bytes) WriteTagAndLength(class int, compound bool, tag int, length int) int {
	return writeTagAndLength(bytes, TagAndLength{Class: class, IsCompound: compound, Tag: tag, Length: length})
}

func (bytes *Bytes) writeString(s string) (size int) {
	size = len(s)
	start := bytes.offset - size
	if start < 0 {
		panic("Not enough space for string")
	}
	copy(bytes.bytes[start:], s)
	bytes.offset = start
	return
}

func (bytes *Bytes) writeBytes(b []byte) (size int) {
	size = len(b)
	start := bytes.offset - size
	if start < 0 {
		panic("Not enough space for bytes")
	}
	copy(bytes.bytes[start:], b)
	bytes.offset = start
	return
}

//
// Parse tag, length and read the a primitive value
// Supported types are:
// - boolean
// - integer (parsed as int32)
// - enumerated (parsed as int32)
// - UTF8 string
// - Octet string
//
// Parameters:
// - class: the expected class value(classUniversal, classApplication, classContextSpecific)
// - tag: the expected tag value
// - typeTag: the real primitive type to parse (tagBoolean, tagInteger, tagEnym, tagUTF8String, tagOctetString)
//
func (bytes *Bytes) ReadPrimitiveSubBytes(class int, tag int, typeTag int) (value interface{}, err error) {
	// Check tag
	tagAndLength, err := bytes.ParseTagAndLength()
	if err != nil {
		err = LdapError{fmt.Sprintf("ReadPrimitiveSubBytes:\n%s", err.Error())}
		return
	}
	err = tagAndLength.Expect(class, tag, isNotCompound)
	if err != nil {
		err = LdapError{fmt.Sprintf("ReadPrimitiveSubBytes:\n%s", err.Error())}
		return
	}

	start := bytes.offset
	end := bytes.offset + tagAndLength.Length

	// Check we got enough bytes to process
	if end > len(bytes.bytes) {
		// err = LdapError{fmt.Sprintf("ReadPrimitiveSubBytes: data truncated: expecting %d bytes at offset %d but only %d bytes are remaining (start: %d, length: %d, end: %d, len(b): %d, bytes: %#+v)", tagAndLength.Length, *b.offset, len(b.bytes)-start, start, tagAndLength.Length, end, len(b.bytes), b.bytes)}
		err = LdapError{fmt.Sprintf("ReadPrimitiveSubBytes: data truncated: expecting %d bytes at offset %d but only %d bytes are remaining", tagAndLength.Length, bytes.offset, len(bytes.bytes)-start)}
		return
	}
	// Process sub-bytes
	subBytes := bytes.bytes[start:end]
	switch typeTag {
	case tagBoolean:
		value, err = parseBool(subBytes)
	case tagInteger:
		value, err = parseInt32(subBytes)
	case tagEnum:
		value, err = parseInt32(subBytes)
	case tagOctetString:
		value, err = parseOctetString(subBytes)
	default:
		err = LdapError{fmt.Sprintf("ReadPrimitiveSubBytes: invalid type tag value %d", typeTag)}
		return
	}
	if err != nil {
		err = LdapError{fmt.Sprintf("ReadPrimitiveSubBytes:\n%s", err.Error())}
		return
	}
	// Move offset
	bytes.offset = end
	return
}

func (bytes *Bytes) Bytes() []byte {
	return bytes.bytes
}
