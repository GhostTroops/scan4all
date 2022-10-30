package dnsutil

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	dnsTimeout time.Duration = 3 * time.Second
)

var roots = []string{"a.root-servers.net", "b.root-servers.net", "d.root-servers.net", "c.root-servers.net", "e.root-servers.net", "f.root-servers.net", "g.root-servers.net", "h.root-servers.net", "i.root-servers.net", "j.root-servers.net", "k.root-servers.net", "l.root-servers.net", "m.root-servers.net"}

//Dig dig
type Dig struct {
	LocalAddr        string
	RemoteAddr       string
	BackupRemoteAddr string
	EDNSSubnet       net.IP
	DialTimeout      time.Duration
	WriteTimeout     time.Duration
	ReadTimeout      time.Duration
	Protocol         string
	Retry            int
	Fallback         bool //if Truncated == true; udp -> tcp
}

func (d *Dig) protocol() string {
	if d.Protocol != "" {
		return d.Protocol
	}
	return "udp"
}

func (d *Dig) dialTimeout() time.Duration {
	if d.DialTimeout != 0 {
		return d.DialTimeout
	}
	return dnsTimeout
}

func (d *Dig) readTimeout() time.Duration {
	if d.ReadTimeout != 0 {
		return d.ReadTimeout
	}
	return dnsTimeout
}

func (d *Dig) writeTimeout() time.Duration {
	if d.WriteTimeout != 0 {
		return d.WriteTimeout
	}
	return dnsTimeout
}

func (d *Dig) retry() int {
	if d.Retry > 0 {
		return d.Retry
	}
	return 1
}

func (d *Dig) remoteAddr() (string, error) {
	_, _, err := net.SplitHostPort(d.RemoteAddr)
	if err != nil {
		if ns, e := nameserver(); e == nil {
			d.RemoteAddr = net.JoinHostPort(ns, "53")
		} else {
			return d.RemoteAddr, fmt.Errorf("bad remoteaddr %v ,forget SetDNS ? : %s", d.RemoteAddr, err)
		}
	}
	return d.RemoteAddr, nil
}

func (d *Dig) conn(ctx context.Context) (net.Conn, error) {
	remoteaddr, err := d.remoteAddr()
	if err != nil {
		return nil, err
	}
	di := net.Dialer{Timeout: d.dialTimeout()}
	if d.LocalAddr != "" {
		di.LocalAddr, err = resolveLocalAddr(d.protocol(), d.LocalAddr)
	}
	return di.DialContext(ctx, d.protocol(), remoteaddr)
}

func resolveLocalAddr(network string, laddr string) (net.Addr, error) {
	network = strings.ToLower(network)
	laddr += ":0"
	switch network {
	case "udp":
		return net.ResolveUDPAddr(network, laddr)
	case "tcp":
		return net.ResolveTCPAddr(network, laddr)
	}
	return nil, errors.New("unknown network:" + network)
}

//NewMsg  返回query msg
func NewMsg(Type uint16, domain string) *dns.Msg {
	return newMsg(Type, domain)
}

func newMsg(Type uint16, domain string) *dns.Msg {
	domain = dns.Fqdn(domain)
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{
		Name:   domain,
		Qtype:  Type,
		Qclass: dns.ClassINET,
	}
	return msg
}

//Exchange 发送msg 接收响应
func (d *Dig) Exchange(m *dns.Msg) (*dns.Msg, error) {
	if d.BackupRemoteAddr != "" {
		return d.raceExchange(m)
	}
	var msg *dns.Msg
	var err error
	for i := 0; i < d.retry(); i++ {
		msg, err = d.exchange(context.TODO(), m)
		if err == nil {
			return msg, err
		}
	}
	return msg, err
}

func (d Dig) UseBackup() Dig {
	d.RemoteAddr, d.BackupRemoteAddr = d.BackupRemoteAddr, ""
	return d
}

type raceResult struct {
	data *dns.Msg
	err  error
}

func (d *Dig) raceExchange(m *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var rspCh = make(chan raceResult, 2)
	go func() {
		rsp, err := d.exchange(ctx, m)
		rspCh <- raceResult{
			data: rsp,
			err:  err,
		}
	}()
	go func() {
		dig := d.UseBackup()
		rsp, err := dig.exchange(ctx, m)
		rspCh <- raceResult{
			data: rsp,
			err:  err,
		}
	}()
	var err error
	var i int
	for rsp := range rspCh {
		i++
		if rsp.err == nil {
			return rsp.data, nil
		}
		err = rsp.err
		if i == 2 {
			break
		}
	}
	close(rspCh)
	return nil, err
}

func (d *Dig) exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	var err error
	c := new(dns.Conn)
	c.Conn, err = d.conn(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetWriteDeadline(time.Now().Add(d.writeTimeout()))
	d.edns0clientsubnet(m)
	err = c.WriteMsg(m)
	if err != nil {
		return nil, err
	}
	c.SetReadDeadline(time.Now().Add(d.readTimeout()))
	res, err := c.ReadMsg()
	if err != nil {
		return nil, err
	}
	if res.Id != m.Id {
		return res, dns.ErrId
	}
	if d.protocol() == "udp" && res.Truncated && d.Fallback {
		dig := *d
		dig.Protocol = "tcp"
		res, err := dig.exchange(ctx, m)
		if err == nil {
			return res, nil
		}
	}
	return res, nil
}

//SetTimeOut set read write dial timeout
func (d *Dig) SetTimeOut(t time.Duration) {
	d.ReadTimeout = t
	d.WriteTimeout = t
	d.DialTimeout = t
}

//SetDNS 设置查询的dns server
//Deprecated: use At
func (d *Dig) SetDNS(host string) error {
	var err error
	d.RemoteAddr, err = d.lookupdns(host)
	return err
}

//At 设置查询的dns server,同SetDNS,只是更加语义化
func (d *Dig) At(host string) error {
	var err error
	d.RemoteAddr, err = d.lookupdns(host)
	return err
}

//SetBackupDNS  设置后查询DNS将同时向两个server发起请求,并响应第一个收到的msg
func (d *Dig) SetBackupDNS(host string) error {
	var err error
	d.BackupRemoteAddr, err = d.lookupdns(host)
	return err
}

func (d *Dig) lookupdns(host string) (string, error) {
	var ip string
	port := "53"
	switch strings.Count(host, ":") {
	case 0: //ipv4 or domain
		ip = host
	case 1: //ipv4 or domain
		var err error
		ip, port, err = net.SplitHostPort(host)
		if err != nil {
			return "", err
		}
	default: //ipv6
		if net.ParseIP(host).To16() != nil {
			ip = host
		} else {
			ip = host[:strings.LastIndex(host, ":")]
			port = host[strings.LastIndex(host, ":")+1:]
		}
	}
	ips, err := net.LookupIP(ip)
	if err != nil {
		return "", err
	}
	for _, addr := range ips {
		return fmt.Sprintf("[%s]:%v", addr, port), nil
	}
	return "", errors.New("no such host")

}

//SetEDNS0ClientSubnet  +client
func (d *Dig) SetEDNS0ClientSubnet(clientip string) error {
	ip := net.ParseIP(clientip)
	if ip.To4() == nil {
		return errors.New("not a ipv4")
	}
	d.EDNSSubnet = ip
	return nil
}

//A dig a
func (d *Dig) A(domain string) ([]*dns.A, error) {
	m := newMsg(dns.TypeA, domain)
	res, err := d.Exchange(m)
	if err != nil {
		return nil, err
	}
	var As []*dns.A
	for _, v := range res.Answer {
		if a, ok := v.(*dns.A); ok {
			As = append(As, a)
		}
	}
	return As, nil
}

//NS dig ns
func (d *Dig) NS(domain string) ([]*dns.NS, error) {
	m := newMsg(dns.TypeNS, domain)
	res, err := d.Exchange(m)
	if err != nil {
		return nil, err
	}
	var Ns []*dns.NS
	for _, v := range res.Answer {
		if ns, ok := v.(*dns.NS); ok {
			Ns = append(Ns, ns)
		}
	}
	return Ns, nil
}

//CNAME dig cname
func (d *Dig) CNAME(domain string) ([]*dns.CNAME, error) {
	m := newMsg(dns.TypeCNAME, domain)
	res, err := d.Exchange(m)
	if err != nil {
		return nil, err
	}
	var C []*dns.CNAME
	for _, v := range res.Answer {
		if c, ok := v.(*dns.CNAME); ok {
			C = append(C, c)
		}
	}
	return C, nil
}

//PTR dig ptr
func (d *Dig) PTR(domain string) ([]*dns.PTR, error) {
	m := newMsg(dns.TypePTR, domain)
	res, err := d.Exchange(m)
	if err != nil {
		return nil, err
	}
	var P []*dns.PTR
	for _, v := range res.Answer {
		if p, ok := v.(*dns.PTR); ok {
			P = append(P, p)
		}
	}
	return P, nil
}

//TXT dig txt
func (d *Dig) TXT(domain string) ([]*dns.TXT, error) {
	m := newMsg(dns.TypeTXT, domain)
	res, err := d.Exchange(m)
	if err != nil {
		return nil, err
	}
	var T []*dns.TXT
	for _, v := range res.Answer {
		if t, ok := v.(*dns.TXT); ok {
			T = append(T, t)
		}
	}
	return T, nil
}

//AAAA dig aaaa
func (d *Dig) AAAA(domain string) ([]*dns.AAAA, error) {
	m := newMsg(dns.TypeAAAA, domain)
	res, err := d.Exchange(m)
	if err != nil {
		return nil, err
	}
	var aaaa []*dns.AAAA
	for _, v := range res.Answer {
		if a, ok := v.(*dns.AAAA); ok {
			aaaa = append(aaaa, a)
		}
	}
	return aaaa, nil
}

//MX dig mx
func (d *Dig) MX(domain string) ([]*dns.MX, error) {
	msg := newMsg(dns.TypeMX, domain)
	res, err := d.Exchange(msg)
	if err != nil {
		return nil, err
	}
	var M []*dns.MX
	for _, v := range res.Answer {
		if m, ok := v.(*dns.MX); ok {
			M = append(M, m)
		}
	}
	return M, nil
}

//SRV dig srv
func (d *Dig) SRV(domain string) ([]*dns.SRV, error) {
	msg := newMsg(dns.TypeSRV, domain)
	res, err := d.Exchange(msg)
	if err != nil {
		return nil, err
	}
	var S []*dns.SRV
	for _, v := range res.Answer {
		if s, ok := v.(*dns.SRV); ok {
			S = append(S, s)
		}
	}
	return S, nil
}

//CAA dig caa
func (d *Dig) CAA(domain string) ([]*dns.CAA, error) {
	msg := newMsg(dns.TypeCAA, domain)
	res, err := d.Exchange(msg)
	if err != nil {
		return nil, err
	}
	var C []*dns.CAA
	for _, v := range res.Answer {
		if c, ok := v.(*dns.CAA); ok {
			C = append(C, c)
		}
	}
	return C, nil
}

//SPF dig spf
func (d *Dig) SPF(domain string) ([]*dns.SPF, error) {
	msg := newMsg(dns.TypeSPF, domain)
	res, err := d.Exchange(msg)
	if err != nil {
		return nil, err
	}
	var S []*dns.SPF
	for _, v := range res.Answer {
		if s, ok := v.(*dns.SPF); ok {
			S = append(S, s)
		}
	}
	return S, nil
}

//GetMsg 返回msg响应体
func (d *Dig) GetMsg(Type uint16, domain string) (*dns.Msg, error) {
	m := newMsg(Type, domain)
	return d.Exchange(m)
}

func (d *Dig) edns0clientsubnet(m *dns.Msg) {
	if d.EDNSSubnet == nil {
		return
	}
	e := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,  //ipv4
		SourceNetmask: 32, //ipv4
		Address:       d.EDNSSubnet,
	}
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.Option = append(o.Option, e)
	m.Extra = append(m.Extra, o)
}

//TraceResponse  dig +trace 响应
type TraceResponse struct {
	Server   string
	ServerIP string
	Msg      *dns.Msg
}

//Trace  类似于 dig +trace -t msqType
func (d *Dig) TraceForRecord(domain string, msgType uint16) ([]TraceResponse, error) {
	var responses = make([]TraceResponse, 0)
	var servers = make([]string, 0, 13)
	var server = randserver(roots)
	for {
		if err := d.SetDNS(server); err != nil {
			return responses, err
		}
		msg, err := d.GetMsg(msgType, domain)
		if err != nil {
			return responses, fmt.Errorf("%s:%v", server, err)
		}
		var rsp TraceResponse
		rsp.Server = server
		rsp.ServerIP = d.RemoteAddr
		rsp.Msg = msg
		responses = append(responses, rsp)
		switch msg.Authoritative {
		case false:
			servers = servers[:0]
			for _, v := range msg.Ns {
				ns, ok := v.(*dns.NS)
				if ok {
					servers = append(servers, ns.Ns)
				}
			}
			if len(servers) == 0 {
				return responses, nil
			}
			server = randserver(servers)
		case true:
			return responses, nil
		}
	}
}

//Trace  类似于 dig +trace
func (d *Dig) Trace(domain string) ([]TraceResponse, error) {
	return d.TraceForRecord(domain, dns.TypeA)
}

func randserver(servers []string) string {
	length := len(servers)
	switch length {
	case 0:
		return ""
	case 1:
		return servers[0]
	}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return servers[r.Intn(length)]
}

//IsPolluted  返回domain是否被污染
func IsPolluted(domain string) (bool, error) {
	var dig Dig
	rsps, err := dig.Trace(domain)
	if err != nil {
		return false, err
	}
	length := len(rsps)
	if length < 1 {
		//should not have happened
		return false, fmt.Errorf("empty message")
	}
	last := rsps[length-1]
	if !last.Msg.Authoritative {
		return true, nil
	}
	return false, nil
}
