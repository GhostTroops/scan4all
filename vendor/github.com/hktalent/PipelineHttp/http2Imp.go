package PipelineHttp

import (
	"crypto/tls"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"time"
)

// for http2
type tConn struct {
	net.Conn
	T io.Writer // receives everything that is read from Conn
}

func (w *tConn) Read(b []byte) (n int, err error) {
	n, err = w.Conn.Read(b)
	w.T.Write(b)
	return
}

func (r *PipelineHttp) GetRawClient4Http2() *http.Client {
	return r.GetClient(r.GetTransport4http2())
}

// get http2 client
func (r *PipelineHttp) GetClient4Http2() *http.Client {
	if nil == r.Client {
		r.Client = r.GetRawClient4Http2()
		r.UseHttp2 = r.Client != nil
		r.ver = 2
	}
	return r.Client
}

/*
Upgrade: h2c
*/
func (r *PipelineHttp) DoUrl4Http24Frame(szUrl, szMethod string, framerCbk func(*http2.Frame, *http.Response, *error) bool, w io.Writer) {
	r.UseHttp2 = true
	client := r.GetClient4Http2()
	res, err := client.Get(szUrl)
	if err != nil {
		framerCbk(nil, res, &err)
		return
	}
	//io.Copy(ioutil.Discard, res.Body)
	defer res.Body.Close() // res.Write(os.Stdout)
	r.httpDataIO(func(frame *http2.Frame, e *error) bool {
		return framerCbk(frame, res, e)
	}, w)
}

//func (r *PipelineHttp) hdec() {
//	hpack.NewDecoder(uint32(4<<10), func(hf hpack.HeaderField) {
//		if hf.Name == name && hf.Value == value {
//			matched = true
//		}
//	})
//}

// dialT returns a connection that writes everything that is read to w.
func (r *PipelineHttp) dialT(w io.Writer) func(network, addr string, cfg *tls.Config) (net.Conn, error) {
	return func(network, addr string, cfg *tls.Config) (net.Conn, error) {
		conn, err := tls.Dial(network, addr, cfg)
		return &tConn{conn, w}, err
	}
}
func (r *PipelineHttp) httpDataIO(framerCbk func(*http2.Frame, *error) bool, w io.Writer) {
	framer := http2.NewFramer(w, r.Buf)
	for {
		f, err := framer.ReadFrame()
		if framerCbk(&f, &err) {
			continue
		} else {
			break
		}
		//if err == io.EOF || err == io.ErrUnexpectedEOF {
		//	break
		//}
		//if nil != err {
		//	log.Println(err, framer.ErrorDetail())
		//}
		//switch err.(type) {
		//case nil:
		//	log.Println(f)
		//case http2.ConnectionError:
		//	// Ignore. There will be many errors of type "PROTOCOL_ERROR, DATA
		//	// frame with stream ID 0". Presumably we are abusing the framer.
		//default:
		//	log.Println(err, framer.ErrorDetail())
		//}
	}
}

// 传输对象配置
func (r *PipelineHttp) GetTransport4http2() http.RoundTripper {
	if r.UseHttp2 {
		var tr http.RoundTripper = &http2.Transport{
			//TLSClientConfig: r.tlsConfig(),
			DialTLS:                    r.dialT(r.Buf),
			DisableCompression:         false,
			AllowHTTP:                  true,
			ReadIdleTimeout:            50 * time.Second,
			PingTimeout:                15 * time.Second,
			WriteByteTimeout:           600 * time.Second,
			StrictMaxConcurrentStreams: true, // true 则全局复用，client时建议全局复用，false则为每一个创建一个链接
			//DialTLS: func(netw, addr string, cfg *tls.Config) (net.Conn, error) {
			//	return net.Dial(netw, addr)
			//},
		}
		return tr
	}
	return nil
}

//func (r *PipelineHttp) tlsConfig() *tls.Config {
//	crt, err := ioutil.ReadFile("./cert/public.crt")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	rootCAs := x509.NewCertPool()
//	rootCAs.AppendCertsFromPEM(crt)
//
//	return &tls.Config{
//		RootCAs:            rootCAs,
//		InsecureSkipVerify: false,
//		ServerName:         "localhost",
//	}
//}
