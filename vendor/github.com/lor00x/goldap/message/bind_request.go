package message

import "fmt"

//        BindRequest ::= [APPLICATION 0] SEQUENCE {
//             version                 INTEGER (1 ..  127),
//             name                    LDAPDN,
//             authentication          AuthenticationChoice }

func (request *BindRequest) Name() LDAPDN {
	return request.name
}

func (request *BindRequest) Authentication() AuthenticationChoice {
	return request.authentication
}

func (request *BindRequest) AuthenticationSimple() OCTETSTRING {
	return request.Authentication().(OCTETSTRING)
}

func (request *BindRequest) AuthenticationChoice() string {
	switch request.Authentication().(type) {
	case OCTETSTRING:
		return "simple"
	case SaslCredentials:
		return "sasl"
	}
	return ""
}

func readBindRequest(bytes *Bytes) (bindrequest BindRequest, err error) {
	err = bytes.ReadSubBytes(classApplication, TagBindRequest, bindrequest.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readBindRequest:\n%s", err.Error())}
		return
	}
	return
}

func (request *BindRequest) readComponents(bytes *Bytes) (err error) {
	request.version, err = readINTEGER(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	if !(request.version >= BindRequestVersionMin && request.version <= BindRequestVersionMax) {
		err = LdapError{fmt.Sprintf("readComponents: invalid version %d, must be between %d and %d", request.version, BindRequestVersionMin, BindRequestVersionMax)}
		return
	}
	request.name, err = readLDAPDN(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	request.authentication, err = readAuthenticationChoice(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	return
}

func (request BindRequest) write(bytes *Bytes) (size int) {
	switch request.authentication.(type) {
	case OCTETSTRING:
		size += request.authentication.(OCTETSTRING).writeTagged(bytes, classContextSpecific, TagAuthenticationChoiceSimple)
	case SaslCredentials:
		size += request.authentication.(SaslCredentials).writeTagged(bytes, classContextSpecific, TagAuthenticationChoiceSaslCredentials)
	default:
		panic(fmt.Sprintf("Unknown authentication choice: %#v", request.authentication))
	}
	size += request.name.write(bytes)
	size += request.version.write(bytes)
	size += bytes.WriteTagAndLength(classApplication, isCompound, TagBindRequest, size)
	return
}

func (request BindRequest) size() (size int) {
	size += request.version.size()
	size += request.name.size()
	switch request.authentication.(type) {
	case OCTETSTRING:
		size += request.authentication.(OCTETSTRING).sizeTagged(TagAuthenticationChoiceSimple)
	case SaslCredentials:
		size += request.authentication.(SaslCredentials).sizeTagged(TagAuthenticationChoiceSaslCredentials)
	default:
		panic(fmt.Sprintf("Unknown authentication choice: %#v", request.authentication))
	}

	size += sizeTagAndLength(TagBindRequest, size)
	return
}
