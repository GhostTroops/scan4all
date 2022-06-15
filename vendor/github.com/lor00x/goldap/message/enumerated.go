package message

import "fmt"

func (enum ENUMERATED) Int() int {
	return int(enum)
}

func readENUMERATED(bytes *Bytes, allowedValues map[ENUMERATED]string) (ret ENUMERATED, err error) {
	var value interface{}
	value, err = bytes.ReadPrimitiveSubBytes(classUniversal, tagEnum, tagEnum)
	if err != nil {
		err = LdapError{fmt.Sprintf("readENUMERATED:\n%s", err.Error())}
		return
	}
	ret = ENUMERATED(value.(int32))
	if _, ok := allowedValues[ret]; !ok {
		err = LdapError{fmt.Sprintf("readENUMERATED: Invalid ENUMERATED VALUE %d", ret)}
		return
	}
	return
}

func (enum ENUMERATED) write(bytes *Bytes) int {
	return bytes.WritePrimitiveSubBytes(classUniversal, tagEnum, enum)
}

func (enum ENUMERATED) writeTagged(bytes *Bytes, class int, tag int) int {
	return bytes.WritePrimitiveSubBytes(class, tag, enum)
}

func (enum ENUMERATED) size() int {
	return SizePrimitiveSubBytes(tagEnum, enum)
}
