package message

import "fmt"

//
//        AssertionValue ::= OCTET STRING

func readAssertionValue(bytes *Bytes) (assertionvalue AssertionValue, err error) {
	var octetstring OCTETSTRING
	octetstring, err = readOCTETSTRING(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readAssertionValue:\n%s", err.Error())}
		return
	}
	assertionvalue = AssertionValue(octetstring)
	return
}

func readTaggedAssertionValue(bytes *Bytes, class int, tag int) (assertionvalue AssertionValue, err error) {
	var octetstring OCTETSTRING
	octetstring, err = readTaggedOCTETSTRING(bytes, class, tag)
	if err != nil {
		err = LdapError{fmt.Sprintf("readTaggedAssertionValue:\n%s", err.Error())}
		return
	}
	assertionvalue = AssertionValue(octetstring)
	return
}

func (assertion AssertionValue) size() int {
	return OCTETSTRING(assertion).size()
}

func (assertion AssertionValue) sizeTagged(tag int) int {
	return OCTETSTRING(assertion).sizeTagged(tag)
}

func (assertion AssertionValue) write(bytes *Bytes) int {
	return OCTETSTRING(assertion).write(bytes)
}

func (assertion AssertionValue) writeTagged(bytes *Bytes, class int, tag int) int {
	return OCTETSTRING(assertion).writeTagged(bytes, class, tag)
}
