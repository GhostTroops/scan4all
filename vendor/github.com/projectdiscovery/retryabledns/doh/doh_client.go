package doh

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/miekg/dns"
)

type Client struct {
	DefaultResolver Resolver
	httpClient      *http.Client
}

func NewWithOptions(options Options) *Client {
	return &Client{DefaultResolver: options.DefaultResolver, httpClient: options.HttpClient}
}

func New() *Client {
	httpClient := NewHttpClientWithTimeout(DefaultTimeout)
	return NewWithOptions(Options{DefaultResolver: Cloudflare, HttpClient: httpClient})
}

func (c *Client) Query(name string, question QuestionType) (*Response, error) {
	return c.QueryWithResolver(c.DefaultResolver, name, question)
}

func (c *Client) QueryWithResolver(r Resolver, name string, question QuestionType) (*Response, error) {
	return c.QueryWithJsonAPI(r, name, question)
}

func (c *Client) QueryWithJsonAPI(r Resolver, name string, question QuestionType) (*Response, error) {
	req, err := http.NewRequest(http.MethodGet, r.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	q := req.URL.Query()
	q.Add("name", name)
	q.Add("type", question.ToString())
	req.URL.RawQuery = q.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.Body == nil {
		return nil, errors.New("empty response body")
	}

	var response Response

	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) QueryWithDOH(method Method, r Resolver, name string, question uint16) (*dns.Msg, error) {
	msg := &dns.Msg{}
	msg.Id = 0
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{
		Name:   dns.Fqdn(name),
		Qtype:  question,
		Qclass: dns.ClassINET,
	}
	return c.QueryWithDOHMsg(method, r, msg)
}

func (c *Client) QueryWithDOHMsg(method Method, r Resolver, msg *dns.Msg) (*dns.Msg, error) {
	packedMsg, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	var body []byte
	var dnsParam string
	switch method {
	case MethodPost:
		dnsParam = ""
		body = packedMsg
	case MethodGet:
		dnsParam = base64.RawURLEncoding.EncodeToString(packedMsg)
		body = nil
	default:
		return nil, errors.New("unsupported method")
	}
	req, err := http.NewRequest(string(method), r.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	if dnsParam != "" {
		q := req.URL.Query()
		q.Add("dns", dnsParam)
		req.URL.RawQuery = q.Encode()
	} else if len(body) > 0 {
		req.Header.Set("Content-Type", "application/dns-message")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.Body == nil {
		return nil, errors.New("empty response body")
	}

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	respMsg := &dns.Msg{}
	if err := respMsg.Unpack(respBodyBytes); err != nil {
		return nil, err
	}
	return respMsg, nil
}
