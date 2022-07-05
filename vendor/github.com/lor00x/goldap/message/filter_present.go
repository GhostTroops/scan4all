package message

import "fmt"

//             present         [7] AttributeDescription,
func readFilterPresent(bytes *Bytes) (ret FilterPresent, err error) {
	var attributedescription AttributeDescription
	attributedescription, err = readTaggedAttributeDescription(bytes, classContextSpecific, TagFilterPresent)
	if err != nil {
		err = LdapError{fmt.Sprintf("readFilterPresent:\n%s", err.Error())}
		return
	}
	ret = FilterPresent(attributedescription)
	return
}

//             present         [7] AttributeDescription,
func (f FilterPresent) write(bytes *Bytes) int {
	return AttributeDescription(f).writeTagged(bytes, classContextSpecific, TagFilterPresent)
}
func (filterAnd FilterPresent) getFilterTag() int {
	return TagFilterPresent
}

//             present         [7] AttributeDescription,
func (f FilterPresent) size() int {
	return AttributeDescription(f).sizeTagged(TagFilterPresent)
}
