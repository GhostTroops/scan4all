package socks5

import (
	"errors"
	"io"
	"log"
)

var (
	// ErrBadReply is the error when read reply
	ErrBadReply = errors.New("Bad Reply")
)

// NewNegotiationRequest return negotiation request packet can be writed into server
func NewNegotiationRequest(methods []byte) *NegotiationRequest {
	return &NegotiationRequest{
		Ver:      Ver,
		NMethods: byte(len(methods)),
		Methods:  methods,
	}
}

// WriteTo write negotiation request packet into server
func (r *NegotiationRequest) WriteTo(w io.Writer) (int64, error) {
	i, err := w.Write(append([]byte{r.Ver, r.NMethods}, r.Methods...))
	if err != nil {
		return 0, err
	}
	if Debug {
		log.Printf("Sent NegotiationRequest: %#v %#v %#v\n", r.Ver, r.NMethods, r.Methods)
	}
	return int64(i), nil
}

// NewNegotiationReplyFrom read negotiation reply packet from server
func NewNegotiationReplyFrom(r io.Reader) (*NegotiationReply, error) {
	bb := make([]byte, 2)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, err
	}
	if bb[0] != Ver {
		return nil, ErrVersion
	}
	if Debug {
		log.Printf("Got NegotiationReply: %#v %#v\n", bb[0], bb[1])
	}
	return &NegotiationReply{
		Ver:    bb[0],
		Method: bb[1],
	}, nil
}

// NewUserPassNegotiationRequest return user password negotiation request packet can be writed into server
func NewUserPassNegotiationRequest(username []byte, password []byte) *UserPassNegotiationRequest {
	return &UserPassNegotiationRequest{
		Ver:    UserPassVer,
		Ulen:   byte(len(username)),
		Uname:  username,
		Plen:   byte(len(password)),
		Passwd: password,
	}
}

// WriteTo write user password negotiation request packet into server
func (r *UserPassNegotiationRequest) WriteTo(w io.Writer) (int64, error) {
	i, err := w.Write(append(append(append([]byte{r.Ver, r.Ulen}, r.Uname...), r.Plen), r.Passwd...))
	if err != nil {
		return 0, err
	}
	if Debug {
		log.Printf("Sent UserNameNegotiationRequest: %#v %#v %#v %#v %#v\n", r.Ver, r.Ulen, r.Uname, r.Plen, r.Passwd)
	}
	return int64(i), nil
}

// NewUserPassNegotiationReplyFrom read user password negotiation reply packet from server
func NewUserPassNegotiationReplyFrom(r io.Reader) (*UserPassNegotiationReply, error) {
	bb := make([]byte, 2)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, err
	}
	if bb[0] != UserPassVer {
		return nil, ErrUserPassVersion
	}
	if Debug {
		log.Printf("Got UserPassNegotiationReply: %#v %#v \n", bb[0], bb[1])
	}
	return &UserPassNegotiationReply{
		Ver:    bb[0],
		Status: bb[1],
	}, nil
}

// NewRequest return request packet can be writed into server, dstaddr should not have domain length
func NewRequest(cmd byte, atyp byte, dstaddr []byte, dstport []byte) *Request {
	if atyp == ATYPDomain {
		dstaddr = append([]byte{byte(len(dstaddr))}, dstaddr...)
	}
	return &Request{
		Ver:     Ver,
		Cmd:     cmd,
		Rsv:     0x00,
		Atyp:    atyp,
		DstAddr: dstaddr,
		DstPort: dstport,
	}
}

// WriteTo write request packet into server
func (r *Request) WriteTo(w io.Writer) (int64, error) {
	i, err := w.Write(append(append([]byte{r.Ver, r.Cmd, r.Rsv, r.Atyp}, r.DstAddr...), r.DstPort...))
	if err != nil {
		return 0, err
	}
	if Debug {
		log.Printf("Sent Request: %#v %#v %#v %#v %#v %#v\n", r.Ver, r.Cmd, r.Rsv, r.Atyp, r.DstAddr, r.DstPort)
	}
	return int64(i), nil
}

// NewReplyFrom read reply packet from server
func NewReplyFrom(r io.Reader) (*Reply, error) {
	bb := make([]byte, 4)
	if _, err := io.ReadFull(r, bb); err != nil {
		return nil, err
	}
	if bb[0] != Ver {
		return nil, ErrVersion
	}
	var addr []byte
	if bb[3] == ATYPIPv4 {
		addr = make([]byte, 4)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
	} else if bb[3] == ATYPIPv6 {
		addr = make([]byte, 16)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
	} else if bb[3] == ATYPDomain {
		dal := make([]byte, 1)
		if _, err := io.ReadFull(r, dal); err != nil {
			return nil, err
		}
		if dal[0] == 0 {
			return nil, ErrBadReply
		}
		addr = make([]byte, int(dal[0]))
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
		addr = append(dal, addr...)
	} else {
		return nil, ErrBadReply
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(r, port); err != nil {
		return nil, err
	}
	if Debug {
		log.Printf("Got Reply: %#v %#v %#v %#v %#v %#v\n", bb[0], bb[1], bb[2], bb[3], addr, port)
	}
	return &Reply{
		Ver:     bb[0],
		Rep:     bb[1],
		Rsv:     bb[2],
		Atyp:    bb[3],
		BndAddr: addr,
		BndPort: port,
	}, nil
}
