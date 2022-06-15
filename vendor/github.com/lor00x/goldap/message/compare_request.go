package message

import "fmt"

//
//        CompareRequest ::= [APPLICATION 14] SEQUENCE {
//             entry           LDAPDN,
//             ava             AttributeValueAssertion }

func (request *CompareRequest) Entry() LDAPDN {
	return request.entry
}

func (request *CompareRequest) Ava() *AttributeValueAssertion {
	return &request.ava
}

func readCompareRequest(bytes *Bytes) (ret CompareRequest, err error) {
	err = bytes.ReadSubBytes(classApplication, TagCompareRequest, ret.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readCompareRequest:\n%s", err.Error())}
		return
	}
	return
}

func (request *CompareRequest) readComponents(bytes *Bytes) (err error) {
	request.entry, err = readLDAPDN(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	request.ava, err = readAttributeValueAssertion(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	return
}

func (request CompareRequest) write(bytes *Bytes) (size int) {
	size += request.ava.write(bytes)
	size += request.entry.write(bytes)
	size += bytes.WriteTagAndLength(classApplication, isCompound, TagCompareRequest, size)
	return
}

func (request CompareRequest) size() (size int) {
	size += request.entry.size()
	size += request.ava.size()
	size += sizeTagAndLength(TagCompareRequest, size)
	return
}
