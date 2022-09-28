// Package message implements reading and writing multipurpose messages.
//
// RFC 2045, RFC 2046 and RFC 2047 defines MIME, and RFC 2183 defines the
// Content-Disposition header field.
//
// Add this import to your package if you want to handle most common charsets
// by default:
//
//   import (
//   	_ "github.com/emersion/go-message/charset"
//   )
package message
