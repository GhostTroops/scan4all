package message

import "fmt"

//
//        LDAPDN ::= LDAPString -- Constrained to <distinguishedName>
//                              -- [RFC4514]

func readLDAPDN(bytes *Bytes) (ret LDAPDN, err error) {
	var str LDAPString
	str, err = readLDAPString(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readLDAPDN:\n%s", err.Error())}
		return
	}
	ret = LDAPDN(str)
	return
}

func readTaggedLDAPDN(bytes *Bytes, class int, tag int) (ret LDAPDN, err error) {
	var ldapstring LDAPString
	ldapstring, err = readTaggedLDAPString(bytes, class, tag)
	if err != nil {
		err = LdapError{fmt.Sprintf("readTaggedLDAPDN:\n%s", err.Error())}
		return
	}
	// @TODO: check RFC4514
	ret = LDAPDN(ldapstring)
	return
}

func (l LDAPDN) Pointer() *LDAPDN { return &l }

func readRelativeLDAPDN(bytes *Bytes) (ret RelativeLDAPDN, err error) {
	var ldapstring LDAPString
	ldapstring, err = readLDAPString(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readRelativeLDAPDN:\n%s", err.Error())}
		return
	}
	// @TODO: check RFC4514
	ret = RelativeLDAPDN(ldapstring)
	return
}

func (l LDAPDN) write(bytes *Bytes) int {
	return LDAPString(l).write(bytes)
}

func (l LDAPDN) writeTagged(bytes *Bytes, class int, tag int) int {
	return LDAPString(l).writeTagged(bytes, class, tag)
}

func (l LDAPDN) size() int {
	return LDAPString(l).size()
}

func (l LDAPDN) sizeTagged(tag int) int {
	return LDAPString(l).sizeTagged(tag)
}
