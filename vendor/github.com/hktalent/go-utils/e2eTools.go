package go_utils

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"github.com/hktalent/PipelineHttp"
	"github.com/pion/webrtc/v3"
	"io/ioutil"
	"log"
	"net/http"
)

const (
	E2ePath = "/e2eRelay"
	// Allows compressing offer/answer to bypass terminal input limits.
	compress = true
)

var PipE = PipelineHttp.NewPipelineHttp()

// 发送通讯信号
func SignalCandidate(addr string, c *webrtc.ICECandidate, hd map[string]string, cbk func(resp *http.Response, err error, szU string), kv ...string) {
	payload := []byte(c.ToJSON().Candidate)
	SendE2eData(addr, payload, hd, cbk, kv...)
}

func SendE2eData(addr string, data []byte, hd map[string]string, cbk func(resp *http.Response, err error, szU string), kv ...string) {
	PipE.DoGetWithClient4SetHd(
		nil,
		addr,
		"POST",
		bytes.NewReader(data),
		cbk, func() map[string]string {
			var m1 = map[string]string{"Content-Type": "application/json; charset=utf-8"}
			for k, v := range hd {
				m1[k] = v
			}
			if nil != kv && 0 < len(kv) {
				for i := 0; i < len(kv); i += 2 {
					m1[kv[i]] = kv[i+1]
				}
			}
			return m1
		}, true)

}

// key 标识不同用户，对等的p2p
func GetPeerConnection(key string, certificates *[]webrtc.Certificate) *webrtc.PeerConnection {
	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: []string{
					"stun:stun.l.google.com:19302",  // 108.177.125.127
					"stun:stun1.l.google.com:19302", // 142.250.21.127
					"stun:stun2.l.google.com:19302", // 172.253.56.127
					"stun:stun3.l.google.com:19302", // 74.125.197.127
					"stun:stun4.l.google.com:19302", // 142.251.2.127
				},
			},
		},
	}
	if nil != certificates && 0 < len(*certificates) {
		config.Certificates = *certificates
	}
	if 0 < len(key) {
		config.PeerIdentity = key
	}

	// Create a new RTCPeerConnection
	peerConnection, err := webrtc.NewPeerConnection(config)
	if err != nil {
		log.Println(err)
		return nil
	}
	return peerConnection
}

// Encode encodes the input in base64
// It can optionally zip the input before encoding
func Encode(obj interface{}) string {
	b, err := Json.Marshal(obj)
	if err != nil {
		panic(err)
	}

	if compress {
		b = zip(b)
	}

	return base64.StdEncoding.EncodeToString(b)
}

// Decode decodes the input from base64
// It can optionally unzip the input after decoding
func Decode(in string, obj interface{}) {
	b, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		panic(err)
	}

	if compress {
		b = unzip(b)
	}

	err = Json.Unmarshal(b, obj)
	if err != nil {
		panic(err)
	}
}

func zip(in []byte) []byte {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	_, err := gz.Write(in)
	if err != nil {
		panic(err)
	}
	err = gz.Flush()
	if err != nil {
		panic(err)
	}
	err = gz.Close()
	if err != nil {
		panic(err)
	}
	return b.Bytes()
}

func unzip(in []byte) []byte {
	var b bytes.Buffer
	_, err := b.Write(in)
	if err != nil {
		panic(err)
	}
	r, err := gzip.NewReader(&b)
	if err != nil {
		panic(err)
	}
	res, err := ioutil.ReadAll(r)
	if err != nil {
		panic(err)
	}
	return res
}
