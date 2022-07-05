package message

import "fmt"

//
//        DelResponse ::= [APPLICATION 11] LDAPResult

func (del *DelResponse) SetResultCode(code int) {
	del.resultCode = ENUMERATED(code)
}

func readDelResponse(bytes *Bytes) (ret DelResponse, err error) {
	var res LDAPResult
	res, err = readTaggedLDAPResult(bytes, classApplication, TagDelResponse)
	if err != nil {
		err = LdapError{fmt.Sprintf("readDelResponse:\n%s", err.Error())}
		return
	}
	ret = DelResponse(res)
	return
}

func (del DelResponse) write(bytes *Bytes) int {
	return LDAPResult(del).writeTagged(bytes, classApplication, TagDelResponse)
}

func (del DelResponse) size() int {
	return LDAPResult(del).sizeTagged(TagDelResponse)
}
