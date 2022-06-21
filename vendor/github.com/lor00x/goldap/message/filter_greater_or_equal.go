package message

import "fmt"

//             greaterOrEqual  [5] AttributeValueAssertion,
func readFilterGreaterOrEqual(bytes *Bytes) (ret FilterGreaterOrEqual, err error) {
	var attributevalueassertion AttributeValueAssertion
	attributevalueassertion, err = readTaggedAttributeValueAssertion(bytes, classContextSpecific, TagFilterGreaterOrEqual)
	if err != nil {
		err = LdapError{fmt.Sprintf("readFilterGreaterOrEqual:\n%s", err.Error())}
		return
	}
	ret = FilterGreaterOrEqual(attributevalueassertion)
	return
}

//             greaterOrEqual  [5] AttributeValueAssertion,
func (filter FilterGreaterOrEqual) write(bytes *Bytes) int {
	return AttributeValueAssertion(filter).writeTagged(bytes, classContextSpecific, TagFilterGreaterOrEqual)
}
func (filter FilterGreaterOrEqual) getFilterTag() int {
	return TagFilterGreaterOrEqual
}

//             greaterOrEqual  [5] AttributeValueAssertion,
func (filter FilterGreaterOrEqual) size() int {
	return AttributeValueAssertion(filter).sizeTagged(TagFilterGreaterOrEqual)
}
func (filter *FilterGreaterOrEqual) AttributeDesc() AttributeDescription {
	return filter.attributeDesc
}
func (filter *FilterGreaterOrEqual) AssertionValue() AssertionValue {
	return filter.assertionValue
}
