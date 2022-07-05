package message

import "fmt"

func readBOOLEAN(bytes *Bytes) (ret BOOLEAN, err error) {
	var value interface{}
	value, err = bytes.ReadPrimitiveSubBytes(classUniversal, tagBoolean, tagBoolean)
	if err != nil {
		err = LdapError{fmt.Sprintf("readBOOLEAN:\n%s", err.Error())}
		return
	}
	ret = BOOLEAN(value.(bool))
	return
}

func (boolean BOOLEAN) write(bytes *Bytes) int {
	return bytes.WritePrimitiveSubBytes(classUniversal, tagBoolean, boolean)
}

func (boolean BOOLEAN) writeTagged(bytes *Bytes, class int, tag int) int {
	return bytes.WritePrimitiveSubBytes(class, tag, boolean)
}

func readTaggedBOOLEAN(bytes *Bytes, class int, tag int) (ret BOOLEAN, err error) {
	var value interface{}
	value, err = bytes.ReadPrimitiveSubBytes(class, tag, tagBoolean)
	if err != nil {
		err = LdapError{fmt.Sprintf("readTaggedBOOLEAN:\n%s", err.Error())}
		return
	}
	ret = BOOLEAN(value.(bool))
	return
}

func SizePrimitiveSubBytes(tag int, value interface{}) (size int) {
	switch value.(type) {
	case BOOLEAN:
		size = sizeBool(bool(value.(BOOLEAN)))
	case INTEGER:
		size = sizeInt32(int32(value.(INTEGER)))
	case ENUMERATED:
		size = sizeInt32(int32(value.(ENUMERATED)))
	case OCTETSTRING:
		size = sizeOctetString([]byte(string(value.(OCTETSTRING))))
	default:
		panic(fmt.Sprintf("SizePrimitiveSubBytes: invalid value type %v", value))
	}
	size += sizeTagAndLength(tag, size)
	return
}

func (boolean BOOLEAN) size() int {
	return SizePrimitiveSubBytes(tagBoolean, boolean)
}

func (boolean BOOLEAN) sizeTagged(tag int) int {
	return SizePrimitiveSubBytes(tag, boolean)
}

func (boolean BOOLEAN) Bool() bool {
	return bool(boolean)
}
