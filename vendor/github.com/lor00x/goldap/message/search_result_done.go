package message

import "fmt"

//
//        SearchResultDone ::= [APPLICATION 5] LDAPResult
func readSearchResultDone(bytes *Bytes) (ret SearchResultDone, err error) {
	var ldapresult LDAPResult
	ldapresult, err = readTaggedLDAPResult(bytes, classApplication, TagSearchResultDone)
	if err != nil {
		err = LdapError{fmt.Sprintf("readSearchResultDone:\n%s", err.Error())}
		return
	}
	ret = SearchResultDone(ldapresult)
	return
}

//
//        SearchResultDone ::= [APPLICATION 5] LDAPResult
func (s SearchResultDone) write(bytes *Bytes) int {
	return LDAPResult(s).writeTagged(bytes, classApplication, TagSearchResultDone)
}

//
//        SearchResultDone ::= [APPLICATION 5] LDAPResult
func (s SearchResultDone) size() int {
	return LDAPResult(s).sizeTagged(TagSearchResultDone)
}
func (l *SearchResultDone) SetResultCode(code int) {
	l.resultCode = ENUMERATED(code)
}
