# smtpd

An SMTP server package written in Go, in the style of the built-in HTTP server. It meets the minimum requirements specified by RFC 2821 & 5321.

It is based on [Brad Fitzpatrick's go-smtpd](https://github.com/bradfitz/go-smtpd). The differences can be summarised as:

* A simplified message handler
* Changes made for RFC compliance
* Testing has been added
* Code refactoring
* TLS support
* RCPT handler
* Authentication support

## Features

* A single message handler for simple mail handling with native data types.
* RFC compliance. It implements the minimum command set, responds to commands and adds a valid Received header to messages as specified in RFC 2821 & 5321.
* Customisable listening address and port. It defaults to listening on all addresses on port 25 if unset.
* Customisable host name and application name. It defaults to the system hostname and "smtpd" application name if they are unset.
* Easy to use TLS support that obeys RFC 3207.
* Authentication support for the CRAM-MD5, LOGIN and PLAIN mechanisms that obeys RFC 4954.

## Usage

In general: create the server and pass a handler function to it as for the HTTP server. The server function has the following definition:

```go
func ListenAndServe(addr string, handler Handler, appname string, hostname string) error
```

For TLS support, add the paths to the certificate and key files as for the HTTP server.

```go
func ListenAndServeTLS(addr string, certFile string, keyFile string, handler Handler, appname string, hostname string) error
```

The handler function must have the following definition:

```go
func handler(remoteAddr net.Addr, from string, to []string, data []byte)
```

The parameters are:

* remoteAddr: remote end of the TCP connection i.e. the mail client's IP address and port.
* from: the email address sent by the client in the MAIL command.
* to: the set of email addresses sent by the client in the RCPT command.
* data: the raw bytes of the mail message.

## TLS Support

SMTP over TLS works slightly differently to how you might expect if you are used to the HTTP protocol. Some helpful links for background information are:

* [SSL vs TLS vs STARTTLS](https://www.fastmail.com/help/technical/ssltlsstarttls.html)
* [Opportunistic TLS](https://en.wikipedia.org/wiki/Opportunistic_TLS)
* [RFC 2487: SMTP Service Extension for Secure SMTP over TLS](https://tools.ietf.org/html/rfc2487)
* [func (*Client) StartTLS](https://golang.org/pkg/net/smtp/#Client.StartTLS)

The TLS support has three server configuration options. The bare minimum requirement to enable TLS is to supply certificate and key files as in the TLS example below.

* TLSConfig

This option allows custom TLS configurations such as [requiring strong ciphers](https://cipherli.st/) or using other certificate creation methods. If a certificate file and a key file are supplied to the ConfigureTLS function, the default TLS configuration for Go will be used. The default value for TLSConfig is nil, which disables TLS support.

* TLSRequired

This option sets whether TLS is optional or required. If set to true, the only allowed commands are NOOP, EHLO, STARTTLS and QUIT (as specified in RFC 3207) until the connection is upgraded to TLS i.e. until STARTTLS is issued. This option is ignored if TLS is not configured i.e. if TLSConfig is nil. The default is false.

* TLSListener

This option sets whether the listening socket requires an immediate TLS handshake after connecting. It is equivalent to using HTTPS in web servers, or the now defunct SMTPS on port 465. This option is ignored if TLS is not configured i.e. if TLSConfig is nil. The default is false.

There is also a related package configuration option.

* Debug

This option determines if the data being read from or written to the client will be logged. This may help with debugging when using encrypted connections. The default is false.

## Authentication Support

The authentication support offers three mechanisms (CRAM-MD5, LOGIN and PLAIN) and has three server configuration options. The bare minimum requirement to enable authentication is to supply an authentication handler function as in the authentication example below.

* AuthHandler

This option provides an authentication handler function which is called to determine the validity of the supplied credentials.

* AuthMechs

This option allows the list of allowed authentication mechanisms to be explicitly set, overriding the default settings.

* AuthRequired

This option sets whether authentication is optional or required. If set to true, the only allowed commands are AUTH, EHLO, HELO, NOOP, RSET and QUIT (as specified in RFC 4954) until the session is authenticated. This option is ignored if authentication is not configured i.e. if AuthHandler is nil. The default is false.

If both TLS and authentication are required, the TLS requirements take priority.

### Notes

RFC 4954 specifies that the LOGIN and PLAIN mechanisms require TLS to be in use as they send the password in plaintext. By default, smtpd follows this requirement, and will not advertise or allow LOGIN and PLAIN until a TLS connection is established. This behaviour can be overridden during testing by using the AuthMechs option. For example, to enable the PLAIN mechanism regardless of TLS:

```go
mechs := map[string]bool{"PLAIN": true}
srv := &smtpd.Server{AuthMechs: mechs, ...}
```

The LOGIN and PLAIN mechanisms send the password to the server, but CRAM-MD5 does not - it sends a hash of the password, with a salt supplied by the server. In order to authenticate a session using CRAM-MD5, the server must have access to the plaintext password so it can hash it with the same salt and compare it to the hash sent by the client. If passwords are stored in a hashed format (and they should be), they cannot be transformed into plaintext, and therefore CRAM-MD5 cannot be used. To disable the CRAM-MD5 mechanism:

```go
mechs := map[string]bool{"CRAM-MD5": false}
srv := &smtpd.Server{AuthMechs: mechs, ...}
```

The Go SMTP client cancels the authentication exchange by sending an asterisk to the server after a failed authentication attempt. The server will ignore this behaviour.

## Example

The following example code creates a new server with the name "MyServerApp" that listens on the localhost address and port 2525. Upon receipt of a new mail message, the handler function parses the mail and prints the subject header.

```go
package main

import (
    "bytes"
    "log"
    "net"
    "net/mail"

    "github.com/mhale/smtpd"
)

func mailHandler(origin net.Addr, from string, to []string, data []byte) {
    msg, _ := mail.ReadMessage(bytes.NewReader(data))
    subject := msg.Header.Get("Subject")
    log.Printf("Received mail from %s for %s with subject %s", from, to[0], subject)
}

func main() {
    smtpd.ListenAndServe("127.0.0.1:2525", mailHandler, "MyServerApp", "")
}
```

## TLS Example

Using the example code above, only the main function would be different to add TLS support.

```go
func main() {
    smtpd.ListenAndServeTLS("127.0.0.1:2525", "/path/to/server.crt", "/path/to/server.key", mailHandler, "MyServerApp", "")
}
```

This allows STARTTLS to be listed as a supported extension and allows clients to upgrade connections to TLS by sending a STARTTLS command.

As the package level helper functions do not set the TLSRequired or TLSListener options for compatibility reasons, manual creation of a Server struct is necessary in order to use them.

## RCPT Handler Example

With the same ```mailHandler``` as above:

```go
func rcptHandler(remoteAddr net.Addr, from string, to string) bool {
    domain = getDomain(to)
    return domain == "mail.example.com"
}

func ListenAndServe(addr string, handler smtpd.Handler, rcpt smtpd.HandlerRcpt) error {
    srv := &smtpd.Server{
        Addr:        addr,
        Handler:     handler,
        HandlerRcpt: rcpt,
        Appname:     "MyServerApp",
        Hostname:    "",
    }
    return srv.ListenAndServe()
}

ListenAndServe("127.0.0.1:2525", mailHandler, rcptHandler)
```

## Authentication Example

With the same ```mailHandler``` as above:

```go
func authHandler(remoteAddr net.Addr, mechanism string, username []byte, password []byte, shared []byte) (bool, error) {
    return string(username) == "valid" && string(password) == "password", nil
}

func ListenAndServe(addr string, handler smtpd.Handler, authHandler smtpd.AuthHandler) error {
    srv := &smtpd.Server{
        Addr:        addr,
        Handler:     handler,
        Appname:     "MyServerApp",
        Hostname:    "",
        AuthHandler: authHandler,
        AuthRequired: true,
    }
    return srv.ListenAndServe()
}

ListenAndServe("127.0.0.1:2525", mailHandler, authHandler)
```

This allows AUTH to be listed as a supported extension, CRAM-MD5 as a supported mechanism, and allows clients to authenticate by sending an AUTH command.

## Testing

The tests cover the supported SMTP command set and line parsing. A single server is created listening on an ephemeral port (52525) for the duration of the tests. Each test creates a new client connection for processing commands.

For the TLS, size and authentication tests, a different server is created with a net.Pipe connection inside each individual test, in order to change the server settings for each test.

The TLS and authentication support has also been manually tested with Go client code, Ruby client code, and macOS's Mail.app.

## Licensing

Some of the code in this package was copied or adapted from code found in [Brad Fitzpatrick's go-smtpd](https://github.com/bradfitz/go-smtpd). As such, those sections of code are subject to their original copyright and license. The remaining code is in the public domain.
