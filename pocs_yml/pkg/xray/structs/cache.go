package structs

import "net/http"

type HttpRequestCache struct {
	Request       *http.Request
	ProtoRequest  *Request
	ProtoResponse *Response
}

type TCPUDPRequestCache struct {
	Response      []byte
	ProtoResponse *Response
}
