package client

import "fmt"

const (
	INFO_CONTINUE           = 100
	INFO_SWITCHING_PROTOCOL = 101
	INFO_PROCESSING         = 102

	SUCCESS_OK                = 200
	SUCCESS_CREATED           = 201
	SUCCESS_ACCEPTED          = 202
	SUCCESS_NON_AUTHORITATIVE = 203
	SUCCESS_NO_CONTENT        = 204
	SUCCESS_RESET_CONTENT     = 205
	SUCCESS_PARTIAL_CONTENT   = 206
	SUCCESS_MULTI_STATUS      = 207

	REDIRECTION_MULTIPLE_CHOICES   = 300
	REDIRECTION_MOVED_PERMANENTLY  = 301
	REDIRECTION_MOVED_TEMPORARILY  = 302
	REDIRECTION_SEE_OTHER          = 303
	REDIRECTION_NOT_MODIFIED       = 304
	REDIRECTION_USE_PROXY          = 305
	REDIRECTION_TEMPORARY_REDIRECT = 307

	CLIENT_ERROR_BAD_REQUEST                     = 400
	CLIENT_ERROR_UNAUTHORIZED                    = 401
	CLIENT_ERROR_PAYMENT_REQUIRED                = 402
	CLIENT_ERROR_FORBIDDEN                       = 403
	CLIENT_ERROR_NOT_FOUND                       = 404
	CLIENT_ERROR_METHOD_NOT_ALLOWED              = 405
	CLIENT_ERROR_NOT_ACCEPTABLE                  = 406
	CLIENT_ERROR_PROXY_AUTHENTIFICATION_REQUIRED = 407
	CLIENT_ERROR_REQUEST_TIMEOUT                 = 408
	CLIENT_ERROR_CONFLICT                        = 409
	CLIENT_ERROR_GONE                            = 410
	CLIENT_ERROR_LENGTH_REQUIRED                 = 411
	CLIENT_ERROR_PRECONDITION_FAILED             = 412
	CLIENT_ERROR_REQUEST_ENTITY_TOO_LARGE        = 413
	CLIENT_ERROR_REQUEST_URI_TOO_LONG            = 414
	CLIENT_ERROR_UNSUPPORTED_MEDIA_TYPE          = 415
	CLIENT_ERROR_REQUESTED_RANGE_NOT_SATISFIABLE = 416
	CLIENT_ERROR_EXPECTATION_FAILED              = 417
	CLIENT_ERROR_UNPROCESSABLE_ENTITY            = 422
	CLIENT_ERROR_LOCKED                          = 423
	CLIENT_ERROR_FAILED_DEPENDENCY               = 424

	SERVER_ERROR_INTERNAL                   = 500
	SERVER_ERROR_NOT_IMPLEMENTED            = 501
	SERVER_ERROR_BAD_GATEWAY                = 502
	SERVER_ERROR_SERVICE_UNAVAILABLE        = 503
	SERVER_ERROR_GATEWAY_TIMEOUT            = 504
	SERVER_ERROR_HTTP_VERSION_NOT_SUPPORTED = 505
	SERVER_ERROR_INSUFFICIENT_STORAGE       = 507
)

// Status represents an HTTP status code.
type Status struct {
	Code   int
	Reason string
}

func (s Status) String() string {
	return fmt.Sprintf("%d %s", s.Code, s.Reason)
}

func (s Status) IsInformational() bool {
	return s.Code >= INFO_CONTINUE && s.Code < SUCCESS_OK
}

func (s Status) IsSuccess() bool {
	return s.Code >= SUCCESS_OK && s.Code < REDIRECTION_MULTIPLE_CHOICES
}

func (s Status) IsRedirect() bool {
	// Per RFC 9110 section 15.4.5 a 304 response is terminated by the end of the header section and it refers to a local resource.
	// No further requests are supposed to be issued after a 304 response is received.
	if s.Code == REDIRECTION_NOT_MODIFIED {
		return false
	}
	return s.Code >= REDIRECTION_MULTIPLE_CHOICES && s.Code < CLIENT_ERROR_BAD_REQUEST
}
func (s Status) IsError() bool {
	return s.Code >= CLIENT_ERROR_BAD_REQUEST
}

func (s Status) IsClientError() bool {
	return s.Code >= CLIENT_ERROR_BAD_REQUEST && s.Code < SERVER_ERROR_INTERNAL
}

func (s Status) IsServerError() bool {
	return s.Code >= SERVER_ERROR_INTERNAL
}
