package PipelineHttp

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/quic-go/quic-go/http3"
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
	r.Client = r.GetClient(r.GetTransport4Http3())
	r.ver = 3
	return r.Client
}
