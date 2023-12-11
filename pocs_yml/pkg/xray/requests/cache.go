package requests

import (
	"fmt"
	"net"
	"net/http"
	"sort"

	"github.com/GhostTroops/scan4all/pocs_yml/pkg/xray/structs"
	"github.com/GhostTroops/scan4all/pocs_yml/utils"
	"github.com/bluele/gcache"
)

var (
	GC gcache.Cache
)

func InitCache(size int) {
	GC = gcache.New(size).ARC().Build()
}

func getHttpRuleHash(req *structs.RuleRequest) string {
	headers := req.Headers
	keys := make([]string, len(headers))
	headerStirng := ""
	i := 0
	for k := range headers {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	for _, k := range keys {
		headerStirng += fmt.Sprintf("%s%s", k, headers[k])
	}

	return "rule_" + utils.MD5(fmt.Sprintf("%s%s%s%s%v", req.Method, req.Path, headerStirng, req.Body, req.FollowRedirects))
}

func XraySetHttpRequestCache(ruleReq *structs.RuleRequest, request *http.Request, protoRequest *structs.Request, protoResponse *structs.Response) bool {

	ruleHash := getHttpRuleHash(ruleReq)

	if cache, err := GC.Get(ruleHash); err != nil {
		if _, ok := cache.(*structs.HttpRequestCache); ok {
			return true
		}
	}

	if err := GC.Set(ruleHash, &structs.HttpRequestCache{
		Request:       request,
		ProtoRequest:  protoRequest,
		ProtoResponse: protoResponse,
	}); err == nil {
		return true
	}

	return false
}

func XrayGetHttpRequestCache(ruleReq *structs.RuleRequest) (*http.Request, *structs.Request, *structs.Response, bool) {
	ruleHash := getHttpRuleHash(ruleReq)

	if cache, err := GC.Get(ruleHash); err == nil {
		if requestCache, ok := cache.(*structs.HttpRequestCache); ok {
			return requestCache.Request, requestCache.ProtoRequest, requestCache.ProtoResponse, true
		} else {
		}
	}

	return nil, nil, nil, false
}

func getConnectionIdHash(connectionId string) string {
	return "connetionID_" + connectionId
}

func XraySetTcpUdpConnectionCache(connectionId string, conn *net.Conn) bool {
	connectionIdHash := getConnectionIdHash(connectionId)
	if err := GC.Set(connectionIdHash, conn); err == nil {
		return true
	}

	return false
}

func XrayGetTcpUdpConnectionCache(connectionId string) (*net.Conn, bool) {
	connectionIdHash := getConnectionIdHash(connectionId)

	if cache, err := GC.Get(connectionIdHash); err == nil {
		if connectionCache, ok := cache.(*net.Conn); ok {
			return connectionCache, true
		} else {
		}
	}

	return nil, false
}

func getTCPUDPResponseHash(content string) string {
	return "tcpudpResponse_" + content
}

func XraySetTcpUdpResponseCache(content string, response []byte, protoResponse *structs.Response) bool {
	responseHash := getTCPUDPResponseHash(content)

	if cache, err := GC.Get(responseHash); err != nil {
		if _, ok := cache.(*structs.TCPUDPRequestCache); ok {
			return true
		}
	}

	if err := GC.Set(responseHash, &structs.TCPUDPRequestCache{
		Response:      response,
		ProtoResponse: protoResponse,
	}); err == nil {
		return true
	}

	return false
}

func XrayGetTcpUdpResponseCache(content string) ([]byte, *structs.Response, bool) {
	responseHash := getTCPUDPResponseHash(content)
	if cache, err := GC.Get(responseHash); err == nil {
		if requestCache, ok := cache.(*structs.TCPUDPRequestCache); ok {
			return requestCache.Response, requestCache.ProtoResponse, true
		} else {
		}
	}

	return nil, nil, false
}
