package message

import (
	"fmt"
)

func ReadLDAPMessage(bytes *Bytes) (message LDAPMessage, err error) {
	err = bytes.ReadSubBytes(classUniversal, tagSequence, message.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("ReadLDAPMessage:\n%s", err.Error())}
		return
	}
	return
}

//
//        END
//
