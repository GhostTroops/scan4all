package message

import (
	"fmt"
	"reflect"
)

//   This appendix is normative.
//
//        Lightweight-Directory-Access-Protocol-V3 {1 3 6 1 1 18}
//        -- Copyright (C) The Internet Society (2006).  This version of
//        -- this ASN.1 module is part of RFC 4511; see the RFC itself
//        -- for full legal notices.
//        DEFINITIONS
//        IMPLICIT TAGS
//        EXTENSIBILITY IMPLIED ::=
//
//        BEGIN
//
//        LDAPMessage ::= SEQUENCE {
//             messageID       MessageID,
//             protocolOp      CHOICE {
//                  bindRequest           BindRequest,
//                  bindResponse          BindResponse,
//                  unbindRequest         UnbindRequest,
//                  searchRequest         SearchRequest,
//                  searchResEntry        SearchResultEntry,
//                  searchResDone         SearchResultDone,
//                  searchResRef          SearchResultReference,
//                  modifyRequest         ModifyRequest,
//                  modifyResponse        ModifyResponse,
//                  addRequest            AddRequest,
//                  addResponse           AddResponse,
//                  delRequest            DelRequest,
//                  delResponse           DelResponse,
//                  modDNRequest          ModifyDNRequest,
//                  modDNResponse         ModifyDNResponse,
//                  compareRequest        CompareRequest,
//                  compareResponse       CompareResponse,
//                  abandonRequest        AbandonRequest,
//                  extendedReq           ExtendedRequest,
//                  extendedResp          ExtendedResponse,
//                  ...,
//                  intermediateResponse  IntermediateResponse },
//             controls       [0] Controls OPTIONAL }
//

func NewLDAPMessage() *LDAPMessage { return &LDAPMessage{} }

func (message *LDAPMessage) readComponents(bytes *Bytes) (err error) {
	message.messageID, err = readMessageID(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	message.protocolOp, err = readProtocolOp(bytes)
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
		if tag.Tag == TagLDAPMessageControls {
			var controls Controls
			controls, err = readTaggedControls(bytes, classContextSpecific, TagLDAPMessageControls)
			if err != nil {
				err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
				return
			}
			message.controls = controls.Pointer()
		}
	}
	return
}

func (m *LDAPMessage) Write() (bytes *Bytes, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = LdapError{fmt.Sprintf("Error in LDAPMessage.Write: %s", e)}
		}
	}()
	// Compute the needed size
	totalSize := m.size()
	// Initialize the structure
	bytes = &Bytes{
		bytes:  make([]byte, totalSize),
		offset: totalSize,
	}

	// Go !
	size := 0
	if m.controls != nil {
		size += m.controls.writeTagged(bytes, classContextSpecific, TagLDAPMessageControls)
	}
	size += m.protocolOp.write(bytes)
	size += m.messageID.write(bytes)
	size += bytes.WriteTagAndLength(classUniversal, isCompound, tagSequence, size)
	// Check
	if size != totalSize || bytes.offset != 0 {
		err = LdapError{fmt.Sprintf("Something went wrong while writing the message ! Size is %d instead of %d, final offset is %d instead of 0", size, totalSize, bytes.offset)}
	}
	return
}
func (m *LDAPMessage) size() (size int) {
	size += m.messageID.size()
	size += m.protocolOp.size()
	if m.controls != nil {
		size += m.controls.sizeTagged(TagLDAPMessageControls)
	}
	size += sizeTagAndLength(tagSequence, size)
	return
}
func (l *LDAPMessage) MessageID() MessageID {
	return l.messageID
}
func (l *LDAPMessage) SetMessageID(ID int) {
	l.messageID = MessageID(ID)
}
func (l *LDAPMessage) Controls() *Controls {
	return l.controls
}
func (l *LDAPMessage) ProtocolOp() ProtocolOp {
	return l.protocolOp
}
func (l *LDAPMessage) ProtocolOpName() string {
	return reflect.TypeOf(l.ProtocolOp()).Name()
}
func (l *LDAPMessage) ProtocolOpType() int {
	switch l.protocolOp.(type) {
	case BindRequest:
		return TagBindRequest
	}
	return 0
}
