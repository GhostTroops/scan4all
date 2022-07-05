package message

import "fmt"

//
//        ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
//             requestName      [0] LDAPOID,
//             requestValue     [1] OCTET STRING OPTIONAL }

func (extended *ExtendedRequest) RequestName() LDAPOID {
	return extended.requestName
}

func (extended *ExtendedRequest) RequestValue() *OCTETSTRING {
	return extended.requestValue
}

func readExtendedRequest(bytes *Bytes) (ret ExtendedRequest, err error) {
	err = bytes.ReadSubBytes(classApplication, TagExtendedRequest, ret.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readExtendedRequest:\n%s", err.Error())}
		return
	}
	return
}

func (extended *ExtendedRequest) readComponents(bytes *Bytes) (err error) {
	extended.requestName, err = readTaggedLDAPOID(bytes, classContextSpecific, TagExtendedRequestName)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	if bytes.HasMoreData() {
		var tag TagAndLength
		tag, err = bytes.PreviewTagAndLength()
		if err != nil {
			err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
			return
		}
		if tag.Tag == TagExtendedRequestValue {
			var requestValue OCTETSTRING
			requestValue, err = readTaggedOCTETSTRING(bytes, classContextSpecific, TagExtendedRequestValue)
			if err != nil {
				err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
				return
			}
			extended.requestValue = requestValue.Pointer()
		}
	}
	return
}

func (extended ExtendedRequest) write(bytes *Bytes) (size int) {
	if extended.requestValue != nil {
		size += extended.requestValue.writeTagged(bytes, classContextSpecific, TagExtendedRequestValue)
	}
	size += extended.requestName.writeTagged(bytes, classContextSpecific, TagExtendedRequestName)
	size += bytes.WriteTagAndLength(classApplication, isCompound, TagExtendedRequest, size)
	return
}

func (extended ExtendedRequest) size() (size int) {
	size += extended.requestName.sizeTagged(TagExtendedRequestName)
	if extended.requestValue != nil {
		size += extended.requestValue.sizeTagged(TagExtendedRequestValue)
	}
	size += sizeTagAndLength(TagExtendedRequest, size)
	return
}
