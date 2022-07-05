package message

import "fmt"

//             lessOrEqual     [6] AttributeValueAssertion,
func readFilterLessOrEqual(bytes *Bytes) (ret FilterLessOrEqual, err error) {
	var attributevalueassertion AttributeValueAssertion
	attributevalueassertion, err = readTaggedAttributeValueAssertion(bytes, classContextSpecific, TagFilterLessOrEqual)
	if err != nil {
		err = LdapError{fmt.Sprintf("readFilterLessOrEqual:\n%s", err.Error())}
		return
	}
	ret = FilterLessOrEqual(attributevalueassertion)
	return
}

//             lessOrEqual     [6] AttributeValueAssertion,
func (f FilterLessOrEqual) write(bytes *Bytes) int {
	return AttributeValueAssertion(f).writeTagged(bytes, classContextSpecific, TagFilterLessOrEqual)
}
func (filterAnd FilterLessOrEqual) getFilterTag() int {
	return TagFilterLessOrEqual
}

//             lessOrEqual     [6] AttributeValueAssertion,
func (f FilterLessOrEqual) size() int {
	return AttributeValueAssertion(f).sizeTagged(TagFilterLessOrEqual)
}
func (a *FilterLessOrEqual) AttributeDesc() AttributeDescription {
	return a.attributeDesc
}
func (a *FilterLessOrEqual) AssertionValue() AssertionValue {
	return a.assertionValue
}
