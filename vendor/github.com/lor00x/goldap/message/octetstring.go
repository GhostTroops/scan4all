package message

import "fmt"

func readOCTETSTRING(bytes *Bytes) (ret OCTETSTRING, err error) {
	var value interface{}
	value, err = bytes.ReadPrimitiveSubBytes(classUniversal, tagOctetString, tagOctetString)
	if err != nil {
		err = LdapError{fmt.Sprintf("readOCTETSTRING:\n%s", err.Error())}
		return
	}
	ret = OCTETSTRING(value.([]byte))
	return
}

func readTaggedOCTETSTRING(bytes *Bytes, class int, tag int) (ret OCTETSTRING, err error) {
	var value interface{}
	value, err = bytes.ReadPrimitiveSubBytes(class, tag, tagOctetString)
	if err != nil {
		err = LdapError{fmt.Sprintf("readTaggedOCTETSTRING:\n%s", err.Error())}
		return
	}
	ret = OCTETSTRING(value.([]byte))
	return
}
func (o OCTETSTRING) Pointer() *OCTETSTRING { return &o }
func (o OCTETSTRING) write(bytes *Bytes) int {
	return bytes.WritePrimitiveSubBytes(classUniversal, tagOctetString, o)
}
func (o OCTETSTRING) writeTagged(bytes *Bytes, class int, tag int) int {
	return bytes.WritePrimitiveSubBytes(class, tag, o)
}
func (o OCTETSTRING) size() int {
	return SizePrimitiveSubBytes(tagOctetString, o)
}
func (o OCTETSTRING) sizeTagged(tag int) int {
	return SizePrimitiveSubBytes(tag, o)
}
func (l OCTETSTRING) String() string {
	return string(l)
}
func (l OCTETSTRING) Bytes() []byte {
	return []byte(l)
}
