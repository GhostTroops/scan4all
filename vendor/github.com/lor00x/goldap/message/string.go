package message

import "fmt"

func readTaggedLDAPString(bytes *Bytes, class int, tag int) (ldapstring LDAPString, err error) {
	var octetstring OCTETSTRING
	octetstring, err = readTaggedOCTETSTRING(bytes, class, tag)
	if err != nil {
		err = LdapError{fmt.Sprintf("readTaggedLDAPString:\n%s", err.Error())}
		return
	}
	ldapstring = LDAPString(octetstring)
	return
}

//        LDAPString ::= OCTET STRING -- UTF-8 encoded,
//                                    -- [ISO10646] characters
func readLDAPString(bytes *Bytes) (ldapstring LDAPString, err error) {
	return readTaggedLDAPString(bytes, classUniversal, tagOctetString)
}

//        LDAPString ::= OCTET STRING -- UTF-8 encoded,
//                                    -- [ISO10646] characters
func (s LDAPString) write(bytes *Bytes) int {
	return OCTETSTRING(s).write(bytes)
}
func (s LDAPString) writeTagged(bytes *Bytes, class int, tag int) int {
	return OCTETSTRING(s).writeTagged(bytes, class, tag)
}

//        LDAPString ::= OCTET STRING -- UTF-8 encoded,
//                                    -- [ISO10646] characters
func (s LDAPString) size() int {
	return OCTETSTRING(s).size()
}
func (s LDAPString) sizeTagged(tag int) int {
	return OCTETSTRING(s).sizeTagged(tag)
}
