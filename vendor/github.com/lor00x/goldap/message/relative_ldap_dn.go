package message

//
//        RelativeLDAPDN ::= LDAPString -- Constrained to <name-component>
//                                      -- [RFC4514]
func (r RelativeLDAPDN) write(bytes *Bytes) int {
	return LDAPString(r).write(bytes)
}

//
//        RelativeLDAPDN ::= LDAPString -- Constrained to <name-component>
//                                      -- [RFC4514]
func (r RelativeLDAPDN) size() int {
	return LDAPString(r).size()
}
