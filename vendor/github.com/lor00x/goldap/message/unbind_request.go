package message

import "fmt"

//
//        UnbindRequest ::= [APPLICATION 2] NULL
func readUnbindRequest(bytes *Bytes) (unbindrequest UnbindRequest, err error) {
	var tagAndLength TagAndLength
	tagAndLength, err = bytes.ParseTagAndLength()
	if err != nil {
		err = LdapError{fmt.Sprintf("readUnbindRequest:\n%s", err.Error())}
		return
	}
	err = tagAndLength.Expect(classApplication, TagUnbindRequest, isNotCompound)
	if err != nil {
		err = LdapError{fmt.Sprintf("readUnbindRequest:\n%s", err.Error())}
		return
	}
	if tagAndLength.Length != 0 {
		err = LdapError{"readUnbindRequest: expecting NULL"}
		return
	}
	return
}

//
//        UnbindRequest ::= [APPLICATION 2] NULL
func (u UnbindRequest) write(bytes *Bytes) (size int) {
	size += bytes.WriteTagAndLength(classApplication, isNotCompound, TagUnbindRequest, 0)
	return
}

//
//        UnbindRequest ::= [APPLICATION 2] NULL
func (u UnbindRequest) size() (size int) {
	size = sizeTagAndLength(TagUnbindRequest, 0)
	return
}
