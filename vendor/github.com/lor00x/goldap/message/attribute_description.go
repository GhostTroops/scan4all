package message

import "fmt"

//
//        AttributeDescription ::= LDAPString
//                                -- Constrained to <attributedescription>
//                                -- [RFC4512]

func (description AttributeDescription) Pointer() *AttributeDescription { return &description }

func readAttributeDescription(bytes *Bytes) (ret AttributeDescription, err error) {
	var ldapstring LDAPString
	ldapstring, err = readLDAPString(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readAttributeDescription:\n%s", err.Error())}
		return
	}
	// @TODO: check RFC4512
	ret = AttributeDescription(ldapstring)
	return
}

func readTaggedAttributeDescription(bytes *Bytes, class int, tag int) (ret AttributeDescription, err error) {
	var ldapstring LDAPString
	ldapstring, err = readTaggedLDAPString(bytes, class, tag)
	// @TODO: check RFC4512
	if err != nil {
		err = LdapError{fmt.Sprintf("readTaggedAttributeDescription:\n%s", err.Error())}
		return
	}
	ret = AttributeDescription(ldapstring)
	return
}

func (description AttributeDescription) size() int {
	return LDAPString(description).size()
}

func (description AttributeDescription) sizeTagged(tag int) int {
	return LDAPString(description).sizeTagged(tag)
}

func (description AttributeDescription) write(bytes *Bytes) int {
	return LDAPString(description).write(bytes)
}

func (description AttributeDescription) writeTagged(bytes *Bytes, class int, tag int) int {
	return LDAPString(description).writeTagged(bytes, class, tag)
}
