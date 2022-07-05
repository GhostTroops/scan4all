package message

import "fmt"

//
//        AttributeSelection ::= SEQUENCE OF selector LDAPString
//                       -- The LDAPString is constrained to
//                       -- <attributeSelector> in Section 4.5.1.8

func readAttributeSelection(bytes *Bytes) (attributeSelection AttributeSelection, err error) {
	err = bytes.ReadSubBytes(classUniversal, tagSequence, attributeSelection.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readAttributeSelection:\n%s", err.Error())}
		return
	}
	return
}
func (selection *AttributeSelection) readComponents(bytes *Bytes) (err error) {
	for bytes.HasMoreData() {
		var ldapstring LDAPString
		ldapstring, err = readLDAPString(bytes)
		// @TOTO: check <attributeSelector> in Section 4.5.1.8
		if err != nil {
			err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
			return
		}
		*selection = append(*selection, ldapstring)
	}
	return
}

func (selection AttributeSelection) write(bytes *Bytes) (size int) {
	for i := len(selection) - 1; i >= 0; i-- {
		size += selection[i].write(bytes)
	}
	size += bytes.WriteTagAndLength(classUniversal, isCompound, tagSequence, size)
	return
}

func (selection AttributeSelection) size() (size int) {
	for _, selector := range selection {
		size += selector.size()
	}
	size += sizeTagAndLength(tagSequence, size)
	return
}
