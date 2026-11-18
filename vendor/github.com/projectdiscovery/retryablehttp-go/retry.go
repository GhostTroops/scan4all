package retryablehttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"regexp"

	"github.com/projectdiscovery/utils/errkit"
)

var (
	// A regular expression to match the error returned by net/http when the
	// configured number of redirects is exhausted. This error isn't typed
	// specifically so we resort to matching on the error string.
	redirectsErrorRegex = regexp.MustCompile(`stopped after \d+ redirects\z`)

	// A regular expression to match the error returned by net/http when the
	// scheme specified in the URL is invalid. This error isn't typed
	// specifically so we resort to matching on the error string.
	schemeErrorRegex = regexp.MustCompile(`unsupported protocol scheme`)
)

// CheckRetry specifies a policy for handling retries. It is called
// following each request with the response and error values returned by
// the http.Client. If CheckRetry returns false, the Client stops retrying
// and returns the response to the caller. If CheckRetry returns an error,
// that error value is returned in lieu of the error from the request. The
// Client will close any response body when retrying, but if the retry is
// aborted it is up to the CheckRetry callback to properly close any
// response body before returning.
type CheckRetry func(ctx context.Context, resp *http.Response, err error) (bool, error)

// DefaultRetryPolicy provides a default callback for Client.CheckRetry, which
// will retry on connection errors and server errors.
func DefaultRetryPolicy() func(ctx context.Context, resp *http.Response, err error) (bool, error) {
	return func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		return CheckRecoverableErrors(ctx, resp, err)
	}
}

// HostSprayRetryPolicy provides a callback for Client.CheckRetry, which
// will retry on connection errors and server errors.
func HostSprayRetryPolicy() func(ctx context.Context, resp *http.Response, err error) (bool, error) {
	return func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		return CheckRecoverableErrors(ctx, resp, err)
	}
}

// Check recoverable errors
func CheckRecoverableErrors(ctx context.Context, resp *http.Response, err error) (bool, error) {
	// do not retry on context.Canceled or context.DeadlineExceeded
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	if err != nil {
		if v, ok := err.(*url.Error); ok {
			// Don't retry if the error was due to too many redirects.
			if redirectsErrorRegex.MatchString(v.Error()) {
				return false, nil
			}

			// Don't retry if the error was due to an invalid protocol scheme.
			if schemeErrorRegex.MatchString(v.Error()) {
				return false, nil
			}
		}
		// Don't retry if the error was due to TLS cert verification failure.
		if isCertificateVerificationError(err) {
			return false, nil
		}
		// look for permanent errors
		if errkit.IsKind(err, errkit.ErrKindNetworkPermanent) {
			// donot retry on permanent network errors
			return false, err
		}
		// The error is likely recoverable so retry.
		return true, nil
	}
	return false, nil
}

// isCertificateVerificationError reports whether err comes from a failed TLS
// certificate verification (unknown authority, hostname mismatch, invalid or
// expired certificate). The same certificate fails again, so a retry does not
// help. Since Go 1.20 crypto/tls wraps these errors in
// *tls.CertificateVerificationError.
func isCertificateVerificationError(err error) bool {
	var verifyErr *tls.CertificateVerificationError
	var unknownAuthorityErr x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	return errors.As(err, &verifyErr) ||
		errors.As(err, &unknownAuthorityErr) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &invalidErr)
}
