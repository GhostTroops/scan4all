## socks5

[中文](README_ZH.md)

[![Go Report Card](https://goreportcard.com/badge/github.com/txthinking/socks5)](https://goreportcard.com/report/github.com/txthinking/socks5)
[![GoDoc](https://godoc.org/github.com/txthinking/socks5?status.svg)](https://godoc.org/github.com/txthinking/socks5)

[🗣 News](https://t.me/txthinking_news)
[💬 Chat](https://join.txthinking.com)
[🩸 Youtube](https://www.youtube.com/txthinking) 
[❤️ Sponsor](https://github.com/sponsors/txthinking)

SOCKS Protocol Version 5 Library.

Full TCP/UDP and IPv4/IPv6 support.
Goals: KISS, less is more, small API, code is like the original protocol.

❤️ A project by [txthinking.com](https://www.txthinking.com)

### Install
```
$ go get github.com/txthinking/socks5
```

### Struct is like concept in protocol

* Negotiation:
    * `type NegotiationRequest struct`
        * `func NewNegotiationRequest(methods []byte)`, in client
        * `func (r *NegotiationRequest) WriteTo(w io.Writer)`, client writes to server
        * `func NewNegotiationRequestFrom(r io.Reader)`, server reads from client
    * `type NegotiationReply struct`
        * `func NewNegotiationReply(method byte)`, in server
        * `func (r *NegotiationReply) WriteTo(w io.Writer)`, server writes to client
        * `func NewNegotiationReplyFrom(r io.Reader)`, client reads from server
* User and password negotiation:
    * `type UserPassNegotiationRequest struct`
        * `func NewUserPassNegotiationRequest(username []byte, password []byte)`, in client
        * `func (r *UserPassNegotiationRequest) WriteTo(w io.Writer)`, client writes to server
        * `func NewUserPassNegotiationRequestFrom(r io.Reader)`, server reads from client
    * `type UserPassNegotiationReply struct`
        * `func NewUserPassNegotiationReply(status byte)`, in server
        * `func (r *UserPassNegotiationReply) WriteTo(w io.Writer)`, server writes to client
        * `func NewUserPassNegotiationReplyFrom(r io.Reader)`, client reads from server
* Request:
    * `type Request struct`
        * `func NewRequest(cmd byte, atyp byte, dstaddr []byte, dstport []byte)`, in client
        * `func (r *Request) WriteTo(w io.Writer)`, client writes to server
        * `func NewRequestFrom(r io.Reader)`, server reads from client
        * After server gets the client's *Request, processes...
* Reply:
    * `type Reply struct`
        * `func NewReply(rep byte, atyp byte, bndaddr []byte, bndport []byte)`, in server
        * `func (r *Reply) WriteTo(w io.Writer)`, server writes to client
        * `func NewReplyFrom(r io.Reader)`, client reads from server
* Datagram:
    * `type Datagram struct`
        * `func NewDatagram(atyp byte, dstaddr []byte, dstport []byte, data []byte)`
        * `func NewDatagramFromBytes(bb []byte)`
        * `func (d *Datagram) Bytes()`

### Advanced API

**Server**. You can process client's request by yourself after reading **Request** from client. Also, here is a advanced interfaces.

* `type Server struct`
* `type Handler interface`
    * `TCPHandle(*Server, *net.TCPConn, *Request) error`
    * `UDPHandle(*Server, *net.UDPAddr, *Datagram) error`

Example:

```
s, _ := NewClassicServer(addr, ip, username, password, tcpTimeout, udpTimeout)
s.ListenAndServe(Handler)
```

* If you want a standard socks5 server, pass in nil
* If you want to handle data by yourself, pass in a custom Handler

**Client**. Here is a client support both TCP and UDP and return net.Conn.

* `type Client struct`

Example:

```
c, _ := socks5.NewClient(server, username, password, tcpTimeout, udpTimeout)
conn, _ := c.Dial(network, addr)
```

### Users:

 * Brook [https://github.com/txthinking/brook](https://github.com/txthinking/brook)
 * Shiliew [https://www.shiliew.com](https://www.shiliew.com)

## License

Licensed under The MIT License
