package message

import "fmt"

//
//        AttributeValueAssertion ::= SEQUENCE {
//             attributeDesc   AttributeDescription,
//             assertionValue  AssertionValue }

func (assertion *AttributeValueAssertion) AttributeDesc() AttributeDescription {
	return assertion.attributeDesc
}

func (assertion *AttributeValueAssertion) AssertionValue() AssertionValue {
	return assertion.assertionValue
}

func readAttributeValueAssertion(bytes *Bytes) (ret AttributeValueAssertion, err error) {
	err = bytes.ReadSubBytes(classUniversal, tagSequence, ret.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readAttributeValueAssertion:\n%s", err.Error())}
		return
	}
	return

}

func readTaggedAttributeValueAssertion(bytes *Bytes, class int, tag int) (ret AttributeValueAssertion, err error) {
	err = bytes.ReadSubBytes(class, tag, ret.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readTaggedAttributeValueAssertion:\n%s", err.Error())}
		return
	}
	return
}

func (assertion *AttributeValueAssertion) readComponents(bytes *Bytes) (err error) {
	assertion.attributeDesc, err = readAttributeDescription(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	assertion.assertionValue, err = readAssertionValue(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	return
}

func (assertion AttributeValueAssertion) write(bytes *Bytes) (size int) {
	size += assertion.assertionValue.write(bytes)
	size += assertion.attributeDesc.write(bytes)
	size += bytes.WriteTagAndLength(classUniversal, isCompound, tagSequence, size)
	return
}

func (assertion AttributeValueAssertion) writeTagged(bytes *Bytes, class int, tag int) (size int) {
	size += assertion.assertionValue.write(bytes)
	size += assertion.attributeDesc.write(bytes)
	size += bytes.WriteTagAndLength(class, isCompound, tag, size)
	return
}

func (assertion AttributeValueAssertion) size() (size int) {
	size += assertion.attributeDesc.size()
	size += assertion.assertionValue.size()
	size += sizeTagAndLength(tagSequence, size)
	return
}

func (assertion AttributeValueAssertion) sizeTagged(tag int) (size int) {
	size += assertion.attributeDesc.size()
	size += assertion.assertionValue.size()
	size += sizeTagAndLength(tag, size)
	return
}
