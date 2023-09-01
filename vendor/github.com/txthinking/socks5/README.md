## socks5

[中文](README_ZH.md)

[![Go Report Card](https://goreportcard.com/badge/github.com/txthinking/socks5)](https://goreportcard.com/report/github.com/txthinking/socks5)
[![GoDoc](https://godoc.org/github.com/txthinking/socks5?status.svg)](https://godoc.org/github.com/txthinking/socks5)

[🗣 News](https://t.me/s/txthinking_news)
[🩸 Youtube](https://www.youtube.com/txthinking)

SOCKS Protocol Version 5 Library.

Full TCP/UDP and IPv4/IPv6 support.
Goals: KISS, less is more, small API, code is like the original protocol.

❤️ A project by [txthinking.com](https://www.txthinking.com)

### Install

```
$ go get github.com/txthinking/socks5
```

### Struct is like concept in protocol

-   Negotiation:
    -   `type NegotiationRequest struct`
        -   `func NewNegotiationRequest(methods []byte)`, in client
        -   `func (r *NegotiationRequest) WriteTo(w io.Writer)`, client writes to server
        -   `func NewNegotiationRequestFrom(r io.Reader)`, server reads from client
    -   `type NegotiationReply struct`
        -   `func NewNegotiationReply(method byte)`, in server
        -   `func (r *NegotiationReply) WriteTo(w io.Writer)`, server writes to client
        -   `func NewNegotiationReplyFrom(r io.Reader)`, client reads from server
-   User and password negotiation:
    -   `type UserPassNegotiationRequest struct`
        -   `func NewUserPassNegotiationRequest(username []byte, password []byte)`, in client
        -   `func (r *UserPassNegotiationRequest) WriteTo(w io.Writer)`, client writes to server
        -   `func NewUserPassNegotiationRequestFrom(r io.Reader)`, server reads from client
    -   `type UserPassNegotiationReply struct`
        -   `func NewUserPassNegotiationReply(status byte)`, in server
        -   `func (r *UserPassNegotiationReply) WriteTo(w io.Writer)`, server writes to client
        -   `func NewUserPassNegotiationReplyFrom(r io.Reader)`, client reads from server
-   Request:
    -   `type Request struct`
        -   `func NewRequest(cmd byte, atyp byte, dstaddr []byte, dstport []byte)`, in client
        -   `func (r *Request) WriteTo(w io.Writer)`, client writes to server
        -   `func NewRequestFrom(r io.Reader)`, server reads from client
        -   After server gets the client's \*Request, processes...
-   Reply:
    -   `type Reply struct`
        -   `func NewReply(rep byte, atyp byte, bndaddr []byte, bndport []byte)`, in server
        -   `func (r *Reply) WriteTo(w io.Writer)`, server writes to client
        -   `func NewReplyFrom(r io.Reader)`, client reads from server
-   Datagram:
    -   `type Datagram struct`
        -   `func NewDatagram(atyp byte, dstaddr []byte, dstport []byte, data []byte)`
        -   `func NewDatagramFromBytes(bb []byte)`
        -   `func (d *Datagram) Bytes()`

### Advanced API

> This can satisfy the classic scenario, and it is still recommended that you choose the above small API to customize for special scenarios.

**Server**: support both TCP and UDP

-   `type Server struct`
-   `type Handler interface`
    -   `TCPHandle(*Server, *net.TCPConn, *Request) error`
    -   `UDPHandle(*Server, *net.UDPAddr, *Datagram) error`

Example:

```
server, _ := NewClassicServer(addr, ip, username, password, tcpTimeout, udpTimeout)
server.ListenAndServe(Handler)
```

**Client**: support both TCP and UDP and return net.Conn

-   `type Client struct`

Example:

```
client, _ := socks5.NewClient(server, username, password, tcpTimeout, udpTimeout)
conn, _ := client.Dial(network, addr)
```

### Projects using this library

-   Brook: https://github.com/txthinking/brook
-   Shiliew: https://www.txthinking.com/shiliew.html
-   dismap: https://github.com/zhzyker/dismap
-   emp3r0r: https://github.com/jm33-m0/emp3r0r
-   hysteria: https://github.com/apernet/hysteria
-   mtg: https://github.com/9seconds/mtg
-   trojan-go: https://github.com/p4gefau1t/trojan-go


## License

Licensed under The MIT License
