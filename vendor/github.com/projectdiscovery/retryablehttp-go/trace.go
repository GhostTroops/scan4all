package retryablehttp

import (
	"time"
)

type TraceEventInfo struct {
	Time time.Time
	Info interface{}
}

type TraceInfo struct {
	GotConn              TraceEventInfo
	DNSDone              TraceEventInfo
	GetConn              TraceEventInfo
	PutIdleConn          TraceEventInfo
	GotFirstResponseByte TraceEventInfo
	Got100Continue       TraceEventInfo
	DNSStart             TraceEventInfo
	ConnectStart         TraceEventInfo
	ConnectDone          TraceEventInfo
	TLSHandshakeStart    TraceEventInfo
	TLSHandshakeDone     TraceEventInfo
	WroteHeaders         TraceEventInfo
	WroteRequest         TraceEventInfo
}
