package message

import "fmt"

//        BindResponse ::= [APPLICATION 1] SEQUENCE {
//             COMPONENTS OF LDAPResult,
//             serverSaslCreds    [7] OCTET STRING OPTIONAL }

func readBindResponse(bytes *Bytes) (bindresponse BindResponse, err error) {
	err = bytes.ReadSubBytes(classApplication, TagBindResponse, bindresponse.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readBindResponse:\n%s", err.Error())}
		return
	}
	return
}

func (response *BindResponse) readComponents(bytes *Bytes) (err error) {
	response.LDAPResult.readComponents(bytes)
	if bytes.HasMoreData() {
		var tag TagAndLength
		tag, err = bytes.PreviewTagAndLength()
		if err != nil {
			err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
			return
		}
		if tag.Tag == TagBindResponseServerSaslCreds {
			var serverSaslCreds OCTETSTRING
			serverSaslCreds, err = readTaggedOCTETSTRING(bytes, classContextSpecific, TagBindResponseServerSaslCreds)
			if err != nil {
				err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
				return
			}
			response.serverSaslCreds = serverSaslCreds.Pointer()
		}
	}
	return
}

func (response BindResponse) write(bytes *Bytes) (size int) {
	if response.serverSaslCreds != nil {
		size += response.serverSaslCreds.writeTagged(bytes, classContextSpecific, TagBindResponseServerSaslCreds)
	}
	size += response.LDAPResult.writeComponents(bytes)
	size += bytes.WriteTagAndLength(classApplication, isCompound, TagBindResponse, size)
	return
}

func (response BindResponse) size() (size int) {
	if response.serverSaslCreds != nil {
		size += response.serverSaslCreds.sizeTagged(TagBindResponseServerSaslCreds)
	}
	size += response.LDAPResult.sizeComponents()
	size += sizeTagAndLength(TagBindResponse, size)
	return
}
