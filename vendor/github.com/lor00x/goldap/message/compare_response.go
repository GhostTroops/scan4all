package message

import "fmt"

//
//        CompareResponse ::= [APPLICATION 15] LDAPResult

func (response *CompareResponse) SetResultCode(code int) {
	response.resultCode = ENUMERATED(code)
}

func readCompareResponse(bytes *Bytes) (ret CompareResponse, err error) {
	var res LDAPResult
	res, err = readTaggedLDAPResult(bytes, classApplication, TagCompareResponse)
	if err != nil {
		err = LdapError{fmt.Sprintf("readCompareResponse:\n%s", err.Error())}
		return
	}
	ret = CompareResponse(res)
	return
}

func (response CompareResponse) write(bytes *Bytes) int {
	return LDAPResult(response).writeTagged(bytes, classApplication, TagCompareResponse)
}

func (response CompareResponse) size() int {
	return LDAPResult(response).sizeTagged(TagCompareResponse)
}
