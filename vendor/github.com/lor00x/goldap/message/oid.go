package message

import "fmt"

//
//
//        LDAPOID ::= OCTET STRING -- Constrained to <numericoid>
//                                 -- [RFC4512]

func (l LDAPOID) String() string {
	return string(l)
}

func (l LDAPOID) Bytes() []byte {
	return []byte(l)
}

func (l LDAPOID) Pointer() *LDAPOID { return &l }

func readTaggedLDAPOID(bytes *Bytes, class int, tag int) (ret LDAPOID, err error) {
	var octetstring OCTETSTRING
	octetstring, err = readTaggedOCTETSTRING(bytes, class, tag)
	if err != nil {
		err = LdapError{fmt.Sprintf("readTaggedLDAPOID:\n%s", err.Error())}
		return
	}
	// @TODO: check RFC4512 for <numericoid>
	ret = LDAPOID(octetstring)
	return
}

func readLDAPOID(bytes *Bytes) (ret LDAPOID, err error) {
	return readTaggedLDAPOID(bytes, classUniversal, tagOctetString)
}

func (l LDAPOID) write(bytes *Bytes) int {
	return OCTETSTRING(l).write(bytes)
}

func (l LDAPOID) writeTagged(bytes *Bytes, class int, tag int) int {
	return OCTETSTRING(l).writeTagged(bytes, class, tag)
}

func (l LDAPOID) size() int {
	return OCTETSTRING(l).size()
}

func (l LDAPOID) sizeTagged(tag int) int {
	return OCTETSTRING(l).sizeTagged(tag)
}
