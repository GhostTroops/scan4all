package message

import "fmt"

//             equalityMatch   [3] AttributeValueAssertion,
func readFilterEqualityMatch(bytes *Bytes) (ret FilterEqualityMatch, err error) {
	var attributevalueassertion AttributeValueAssertion
	attributevalueassertion, err = readTaggedAttributeValueAssertion(bytes, classContextSpecific, TagFilterEqualityMatch)
	if err != nil {
		err = LdapError{fmt.Sprintf("readFilterEqualityMatch:\n%s", err.Error())}
		return
	}
	ret = FilterEqualityMatch(attributevalueassertion)
	return
}

//             equalityMatch   [3] AttributeValueAssertion,
func (f FilterEqualityMatch) write(bytes *Bytes) int {
	return AttributeValueAssertion(f).writeTagged(bytes, classContextSpecific, TagFilterEqualityMatch)
}
func (filter FilterEqualityMatch) getFilterTag() int {
	return TagFilterEqualityMatch
}

//             equalityMatch   [3] AttributeValueAssertion,
func (f FilterEqualityMatch) size() int {
	return AttributeValueAssertion(f).sizeTagged(TagFilterEqualityMatch)
}
func (a *FilterEqualityMatch) AttributeDesc() AttributeDescription {
	return a.attributeDesc
}
func (a *FilterEqualityMatch) AssertionValue() AssertionValue {
	return a.assertionValue
}
