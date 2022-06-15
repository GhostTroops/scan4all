package message

import "fmt"

//             approxMatch     [8] AttributeValueAssertion,
func readFilterApproxMatch(bytes *Bytes) (ret FilterApproxMatch, err error) {
	var attributevalueassertion AttributeValueAssertion
	attributevalueassertion, err = readTaggedAttributeValueAssertion(bytes, classContextSpecific, TagFilterApproxMatch)
	if err != nil {
		err = LdapError{fmt.Sprintf("readFilterApproxMatch:\n%s", err.Error())}
		return
	}
	ret = FilterApproxMatch(attributevalueassertion)
	return
}

//             approxMatch     [8] AttributeValueAssertion,
func (f FilterApproxMatch) write(bytes *Bytes) int {
	return AttributeValueAssertion(f).writeTagged(bytes, classContextSpecific, TagFilterApproxMatch)
}
func (filterAnd FilterApproxMatch) getFilterTag() int {
	return TagFilterApproxMatch
}

//             approxMatch     [8] AttributeValueAssertion,
func (f FilterApproxMatch) size() int {
	return AttributeValueAssertion(f).sizeTagged(TagFilterApproxMatch)
}
func (a *FilterApproxMatch) AttributeDesc() AttributeDescription {
	return a.attributeDesc
}
func (a *FilterApproxMatch) AssertionValue() AssertionValue {
	return a.assertionValue
}
