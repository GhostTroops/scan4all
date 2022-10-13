package PipelineHttp

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/lucas-clemente/quic-go/http3"
	"log"
	"net/http"
)

// 在线测试http3 https://geekflare.com/tools/http3-test
func (r *PipelineHttp) GetTransport4Http3() http.RoundTripper {
	pool, err := x509.SystemCertPool()
	if nil != err {
		log.Println(err)
		return nil
	}
	var tr http.RoundTripper = &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: true,
		},
	}
	return tr
}

// get http3 client
func (r *PipelineHttp) GetClient4Http3() *http.Client {
	if nil == r.Client {
		r.Client = r.GetClient(r.GetTransport4Http3())
	}
	return r.Client
}
