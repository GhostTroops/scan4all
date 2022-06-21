package message

import "fmt"

//
//        ModifyResponse ::= [APPLICATION 7] LDAPResult
func readModifyResponse(bytes *Bytes) (ret ModifyResponse, err error) {
	var res LDAPResult
	res, err = readTaggedLDAPResult(bytes, classApplication, TagModifyResponse)
	if err != nil {
		err = LdapError{fmt.Sprintf("readModifyResponse:\n%s", err.Error())}
		return
	}
	ret = ModifyResponse(res)
	return
}
func (l LDAPResult) writeTagged(bytes *Bytes, class int, tag int) (size int) {
	size += l.writeComponents(bytes)
	size += bytes.WriteTagAndLength(class, isCompound, tag, size)
	return
}

//
//        ModifyResponse ::= [APPLICATION 7] LDAPResult
func (m ModifyResponse) write(bytes *Bytes) int {
	return LDAPResult(m).writeTagged(bytes, classApplication, TagModifyResponse)
}

//
//        ModifyResponse ::= [APPLICATION 7] LDAPResult
func (m ModifyResponse) size() int {
	return LDAPResult(m).sizeTagged(TagModifyResponse)
}
func (l *ModifyResponse) SetResultCode(code int) {
	l.resultCode = ENUMERATED(code)
}
