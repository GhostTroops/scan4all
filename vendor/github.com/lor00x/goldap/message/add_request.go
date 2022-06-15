package message

import "fmt"

//
//        AddRequest ::= [APPLICATION 8] SEQUENCE {
//             entry           LDAPDN,
//             attributes      AttributeList }

func (add *AddRequest) Entry() LDAPDN {
	return add.entry
}

func (add *AddRequest) Attributes() AttributeList {
	return add.attributes
}

func readAddRequest(bytes *Bytes) (ret AddRequest, err error) {
	err = bytes.ReadSubBytes(classApplication, TagAddRequest, ret.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readAddRequest:\n%s", err.Error())}
		return
	}
	return
}

func (add *AddRequest) readComponents(bytes *Bytes) (err error) {
	add.entry, err = readLDAPDN(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	add.attributes, err = readAttributeList(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	return
}

func (add AddRequest) size() (size int) {
	size += add.entry.size()
	size += add.attributes.size()
	size += sizeTagAndLength(TagAddRequest, size)
	return
}

func (add AddRequest) write(bytes *Bytes) (size int) {
	size += add.attributes.write(bytes)
	size += add.entry.write(bytes)
	size += bytes.WriteTagAndLength(classApplication, isCompound, TagAddRequest, size)
	return
}
