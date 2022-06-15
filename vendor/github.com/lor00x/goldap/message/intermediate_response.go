package message

import "fmt"

//
//        IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
//             responseName     [0] LDAPOID OPTIONAL,
//             responseValue    [1] OCTET STRING OPTIONAL }
func readIntermediateResponse(bytes *Bytes) (ret IntermediateResponse, err error) {
	err = bytes.ReadSubBytes(classApplication, TagIntermediateResponse, ret.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readIntermediateResponse:\n%s", err.Error())}
		return
	}
	return
}
func (bytes *Bytes) PreviewTagAndLength() (tagAndLength TagAndLength, err error) {
	previousOffset := bytes.offset // Save offset
	tagAndLength, err = bytes.ParseTagAndLength()
	bytes.offset = previousOffset // Restore offset
	return
}
func (res *IntermediateResponse) readComponents(bytes *Bytes) (err error) {
	if bytes.HasMoreData() {
		var tag TagAndLength
		tag, err = bytes.PreviewTagAndLength()
		if err != nil {
			err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
			return
		}
		if tag.Tag == TagIntermediateResponseName {
			var oid LDAPOID
			oid, err = readTaggedLDAPOID(bytes, classContextSpecific, TagIntermediateResponseName)
			if err != nil {
				err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
				return
			}
			res.responseName = oid.Pointer()
		}
	}
	if bytes.HasMoreData() {
		var tag TagAndLength
		tag, err = bytes.PreviewTagAndLength()
		if err != nil {
			err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
			return
		}
		if tag.Tag == TagIntermediateResponseValue {
			var str OCTETSTRING
			str, err = readTaggedOCTETSTRING(bytes, classContextSpecific, TagIntermediateResponseValue)
			if err != nil {
				err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
				return
			}
			res.responseValue = str.Pointer()
		}
	}
	return
}

//
//        IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
//             responseName     [0] LDAPOID OPTIONAL,
//             responseValue    [1] OCTET STRING OPTIONAL }
func (i IntermediateResponse) write(bytes *Bytes) (size int) {
	if i.responseValue != nil {
		size += i.responseValue.writeTagged(bytes, classContextSpecific, TagIntermediateResponseValue)
	}
	if i.responseName != nil {
		size += i.responseName.writeTagged(bytes, classContextSpecific, TagIntermediateResponseName)
	}
	size += bytes.WriteTagAndLength(classApplication, isCompound, TagIntermediateResponse, size)
	return
}

//
//        IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
//             responseName     [0] LDAPOID OPTIONAL,
//             responseValue    [1] OCTET STRING OPTIONAL }
func (i IntermediateResponse) size() (size int) {
	if i.responseName != nil {
		size += i.responseName.sizeTagged(TagIntermediateResponseName)
	}
	if i.responseValue != nil {
		size += i.responseValue.sizeTagged(TagIntermediateResponseValue)
	}
	size += sizeTagAndLength(TagIntermediateResponse, size)
	return
}
