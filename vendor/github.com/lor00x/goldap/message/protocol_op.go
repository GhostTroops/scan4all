package message

import "fmt"

func readProtocolOp(bytes *Bytes) (ret ProtocolOp, err error) {
	tagAndLength, err := bytes.PreviewTagAndLength()
	if err != nil {
		err = LdapError{fmt.Sprintf("readProtocolOp:\n%s", err.Error())}
		return
	}
	switch tagAndLength.Tag {
	case TagBindRequest:
		ret, err = readBindRequest(bytes)
	case TagBindResponse:
		ret, err = readBindResponse(bytes)
	case TagUnbindRequest:
		ret, err = readUnbindRequest(bytes)
	case TagSearchRequest:
		ret, err = readSearchRequest(bytes)
	case TagSearchResultEntry:
		ret, err = readSearchResultEntry(bytes)
	case TagSearchResultDone:
		ret, err = readSearchResultDone(bytes)
	case TagSearchResultReference:
		ret, err = readSearchResultReference(bytes)
	case TagModifyRequest:
		ret, err = readModifyRequest(bytes)
	case TagModifyResponse:
		ret, err = readModifyResponse(bytes)
	case TagAddRequest:
		ret, err = readAddRequest(bytes)
	case TagAddResponse:
		ret, err = readAddResponse(bytes)
	case TagDelRequest:
		ret, err = readDelRequest(bytes)
	case TagDelResponse:
		ret, err = readDelResponse(bytes)
	case TagModifyDNRequest:
		ret, err = readModifyDNRequest(bytes)
	case TagModifyDNResponse:
		ret, err = readModifyDNResponse(bytes)
	case TagCompareRequest:
		ret, err = readCompareRequest(bytes)
	case TagCompareResponse:
		ret, err = readCompareResponse(bytes)
	case TagAbandonRequest:
		ret, err = readAbandonRequest(bytes)
	case TagExtendedRequest:
		ret, err = readExtendedRequest(bytes)
	case TagExtendedResponse:
		ret, err = readExtendedResponse(bytes)
	case TagIntermediateResponse:
		ret, err = readIntermediateResponse(bytes)
	default:
		err = LdapError{fmt.Sprintf("readProtocolOp: invalid tag value %d for protocolOp", tagAndLength.Tag)}
		return
	}
	if err != nil {
		err = LdapError{fmt.Sprintf("readProtocolOp:\n%s", err.Error())}
		return
	}
	return
}
