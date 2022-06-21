package message

import "fmt"

//
//        AuthenticationChoice ::= CHOICE {
//             simple                  [0] OCTET STRING,
//                                     -- 1 and 2 reserved
//             sasl                    [3] SaslCredentials,
//             ...  }

func readAuthenticationChoice(bytes *Bytes) (ret AuthenticationChoice, err error) {
	tagAndLength, err := bytes.PreviewTagAndLength()
	if err != nil {
		err = LdapError{fmt.Sprintf("readAuthenticationChoice:\n%s", err.Error())}
		return
	}
	err = tagAndLength.ExpectClass(classContextSpecific)
	if err != nil {
		err = LdapError{fmt.Sprintf("readAuthenticationChoice:\n%s", err.Error())}
		return
	}
	switch tagAndLength.Tag {
	case TagAuthenticationChoiceSimple:
		ret, err = readTaggedOCTETSTRING(bytes, classContextSpecific, TagAuthenticationChoiceSimple)
	case TagAuthenticationChoiceSaslCredentials:
		ret, err = readSaslCredentials(bytes)
	default:
		err = LdapError{fmt.Sprintf("readAuthenticationChoice: invalid tag value %d for AuthenticationChoice", tagAndLength.Tag)}
		return
	}
	if err != nil {
		err = LdapError{fmt.Sprintf("readAuthenticationChoice:\n%s", err.Error())}
		return
	}
	return
}
