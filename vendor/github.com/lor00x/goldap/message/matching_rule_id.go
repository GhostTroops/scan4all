package message

import "fmt"

//
//        MatchingRuleId ::= LDAPString
func readTaggedMatchingRuleId(bytes *Bytes, class int, tag int) (matchingruleid MatchingRuleId, err error) {
	var ldapstring LDAPString
	ldapstring, err = readTaggedLDAPString(bytes, class, tag)
	if err != nil {
		err = LdapError{fmt.Sprintf("readTaggedMatchingRuleId:\n%s", err.Error())}
		return
	}
	matchingruleid = MatchingRuleId(ldapstring)
	return
}
func (m MatchingRuleId) Pointer() *MatchingRuleId { return &m }

//
//        MatchingRuleId ::= LDAPString
func (m MatchingRuleId) writeTagged(bytes *Bytes, class int, tag int) int {
	return LDAPString(m).writeTagged(bytes, class, tag)
}

//
//        MatchingRuleId ::= LDAPString
func (m MatchingRuleId) sizeTagged(tag int) int {
	return LDAPString(m).sizeTagged(tag)
}
