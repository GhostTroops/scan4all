package cel

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	structs2 "github.com/GhostTroops/scan4all/pocs_yml/pkg/common/structs"
	"github.com/GhostTroops/scan4all/pocs_yml/utils"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/GhostTroops/scan4all/pocs_yml/pkg/xray/requests"
	"github.com/GhostTroops/scan4all/pocs_yml/pkg/xray/structs"
	"github.com/dlclark/regexp2"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
)

var (
	ReversePool = sync.Pool{
		New: func() interface{} {
			return new(structs.Reverse)
		},
	}

	StandradProgramOption = []cel.ProgramOption{
		cel.Functions(
			&functions.Overload{
				Operator: "bytes_bcontains_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bcontains", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bcontains", rhs.Type())
					}
					return types.Bool(bytes.Contains(v1, v2))
				},
			},
			&functions.Overload{
				Operator: "bytes_ibcontains_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bcontains", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bcontains", rhs.Type())
					}
					return types.Bool(bytes.Contains(bytes.ToLower(v1), bytes.ToLower(v2)))
				},
			},
			&functions.Overload{
				Operator: "icontains_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bcontains", lhs.Type())
					}
					v2, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bcontains", rhs.Type())
					}
					// 不区分大小写包含
					return types.Bool(strings.Contains(strings.ToLower(string(v1)), strings.ToLower(string(v2))))
				},
			},
			&functions.Overload{
				Operator: "bytes_bstartsWith_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bstartsWith", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bstartsWith", rhs.Type())
					}
					return types.Bool(bytes.HasPrefix(v1, v2))
				},
			},
			&functions.Overload{
				Operator: "string_bmatches_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					var isMatch = false
					var err error

					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bmatches", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bmatches", rhs.Type())
					}
					re := regexp2.MustCompile(string(v1), 0)
					if isMatch, err = re.MatchString(string([]byte(v2))); err != nil {
						return types.NewErr("%v", err)
					}
					return types.Bool(isMatch)
				},
			},
			&functions.Overload{
				Operator: "matches_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					var (
						isMatch = false
						err     error
					)

					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to matches", lhs.Type())
					}
					v2, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to matches", rhs.Type())
					}

					re := regexp2.MustCompile(string(v1), 0)
					if isMatch, err = re.MatchString(string(v2)); err != nil {
						return types.NewErr("%v", err)
					}
					return types.Bool(isMatch)
				},
			},

			&functions.Overload{
				Operator: "md5_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to md5_string", value.Type())
					}
					return types.String(fmt.Sprintf("%x", md5.Sum([]byte(v))))
				},
			},
			&functions.Overload{
				Operator: "randomInt_int_int",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					from, ok := lhs.(types.Int)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to randomInt", lhs.Type())
					}
					to, ok := rhs.(types.Int)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to randomInt", rhs.Type())
					}
					min, max := int(from), int(to)
					return types.Int(rand.Intn(max-min) + min)
				},
			},
			&functions.Overload{
				Operator: "randomLowercase_int",
				Unary: func(value ref.Val) ref.Val {
					n, ok := value.(types.Int)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to randomLowercase", value.Type())
					}
					return types.String(utils.RandomStr(utils.AsciiLowercase, int(n)))
				},
			},
			&functions.Overload{
				Operator: "base64_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64_string", value.Type())
					}
					return types.String(base64.StdEncoding.EncodeToString([]byte(v)))
				},
			},
			&functions.Overload{
				Operator: "base64_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64_bytes", value.Type())
					}
					return types.String(base64.StdEncoding.EncodeToString(v))
				},
			},
			&functions.Overload{
				Operator: "base64Decode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64Decode_string", value.Type())
					}
					decodeBytes, err := base64.StdEncoding.DecodeString(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeBytes)
				},
			},
			&functions.Overload{
				Operator: "base64Decode_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64Decode_bytes", value.Type())
					}
					decodeBytes, err := base64.StdEncoding.DecodeString(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeBytes)
				},
			},
			&functions.Overload{
				Operator: "urlencode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_string", value.Type())
					}
					return types.String(url.QueryEscape(string(v)))
				},
			},
			&functions.Overload{
				Operator: "urlencode_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_bytes", value.Type())
					}
					return types.String(url.QueryEscape(string(v)))
				},
			},
			&functions.Overload{
				Operator: "urldecode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urldecode_string", value.Type())
					}
					decodeString, err := url.QueryUnescape(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeString)
				},
			},
			&functions.Overload{
				Operator: "urldecode_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urldecode_bytes", value.Type())
					}
					decodeString, err := url.QueryUnescape(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeString)
				},
			},
			&functions.Overload{
				Operator: "substr_string_int_int",
				Function: func(values ...ref.Val) ref.Val {
					if len(values) == 3 {
						str, ok := values[0].(types.String)
						if !ok {
							return types.NewErr("invalid string to 'substr'")
						}
						start, ok := values[1].(types.Int)
						if !ok {
							return types.NewErr("invalid start to 'substr'")
						}
						length, ok := values[2].(types.Int)
						if !ok {
							return types.NewErr("invalid length to 'substr'")
						}
						runes := []rune(str)
						if start < 0 || length < 0 || int(start+length) > len(runes) {
							return types.NewErr("invalid start or length to 'substr'")
						}
						return types.String(runes[start : start+length])
					} else {
						return types.NewErr("too many arguments to 'substr'")
					}
				},
			},
			&functions.Overload{
				Operator: "reverse_wait_int",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					reverse, ok := lhs.Value().(*structs.Reverse)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to 'wait'", lhs.Type())
					}
					timeout, ok := rhs.Value().(int64)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to 'wait'", rhs.Type())
					}

					return types.Bool(reverseCheck(reverse, timeout))
				},
			},
			&functions.Overload{
				Operator: "replaceAll_string_string_string",
				Function: func(values ...ref.Val) ref.Val {
					s, ok := values[0].(types.String)
					if !ok {
						return types.ValOrErr(s, "unexpected type '%v' passed to replaceAll", s.Type())
					}
					old, ok := values[1].(types.String)
					if !ok {
						return types.ValOrErr(old, "unexpected type '%v' passed to replaceAll", old.Type())
					}
					new, ok := values[2].(types.String)
					if !ok {
						return types.ValOrErr(new, "unexpected type '%v' passed to replaceAll", new.Type())
					}

					return types.String(strings.ReplaceAll(string(s), string(old), string(new)))
				},
			},
			&functions.Overload{
				Operator: "printable_string",
				Unary: func(value ref.Val) ref.Val {
					s, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(s, "unexpected type '%v' passed to printable", s.Type())
					}

					clean := strings.Map(func(r rune) rune {
						if unicode.IsPrint(r) {
							return r
						}
						return -1
					}, string(s))

					return types.String(clean)
				},
			},
			&functions.Overload{
				Operator: "sleep_int",
				Unary: func(value ref.Val) ref.Val {
					i, ok := value.(types.Int)
					if !ok {
						return types.ValOrErr(i, "unexpected type '%v' passed to sleep", i.Type())
					}
					time.Sleep(time.Duration(int64(i)) * time.Second)
					return types.Bool(true)
				},
			},
			&functions.Overload{
				Operator: "faviconHash_stringOrBytes",
				Unary: func(value ref.Val) ref.Val {
					b, ok := value.(types.Bytes)
					if !ok {
						bStr, ok := value.(types.String)
						b = []byte(bStr)
						if !ok {
							return types.ValOrErr(bStr, "unexpected type '%v' passed to faviconHash", bStr.Type())
						}
					}

					return types.Int(utils.Mmh3Hash32(utils.Base64Encode(b)))
				},
			},
			&functions.Overload{
				Operator: "toUintString_string_string",
				Function: func(values ...ref.Val) ref.Val {
					s1, ok := values[0].(types.String)
					s := string(s1)
					if !ok {
						return types.ValOrErr(s1, "unexpected type '%v' passed to toUintString", s1.Type())
					}
					direction, ok := values[1].(types.String)
					if !ok {
						return types.ValOrErr(direction, "unexpected type '%v' passed to toUintString", direction.Type())
					}
					if direction == "<" {
						s = utils.ReverseString(s)
					}
					if _, err := strconv.Atoi(s); err == nil {
						return types.String(s)
					} else {
						return types.NewErr("%v", err)
					}
				},
			},
		),
	}
)

func NewFunctionImplOptions(reg ref.TypeRegistry) []cel.ProgramOption {
	newOptions := []cel.ProgramOption{
		cel.Functions(
			&functions.Overload{
				Operator: "string_submatch_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					var (
						resultMap = make(map[string]string)
					)

					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to submatch", lhs.Type())
					}
					v2, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to submatch", rhs.Type())
					}

					re := regexp2.MustCompile(string(v1), regexp2.RE2)
					if m, _ := re.FindStringMatch(string(v2)); m != nil {
						gps := m.Groups()
						for n, gp := range gps {
							if n == 0 {
								continue
							}
							resultMap[gp.Name] = gp.String()
						}
					}
					return types.NewStringStringMap(reg, resultMap)
				},
			},
			&functions.Overload{
				Operator: "string_bsubmatch_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					var (
						resultMap = make(map[string]string)
					)

					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bsubmatch", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bsubmatch", rhs.Type())
					}

					re := regexp2.MustCompile(string(v1), regexp2.RE2)
					if m, _ := re.FindStringMatch(string([]byte(v2))); m != nil {
						gps := m.Groups()
						for n, gp := range gps {
							if n == 0 {
								continue
							}
							resultMap[gp.Name] = gp.String()
						}
					}

					return types.NewStringStringMap(reg, resultMap)
				},
			},
			&functions.Overload{
				Operator: "newReverse",
				Function: func(values ...ref.Val) ref.Val {
					return reg.NativeToValue(xrayNewReverse())
				},
			},
		),
	}

	newOptions = append(newOptions, StandradProgramOption...)

	return newOptions
}

// xray dns反连平台 目前只支持dnslog.cn和ceye.io
func xrayNewReverse() (reverse *structs.Reverse) {
	var (
		urlStr string
	)
	reverse = ReversePool.Get().(*structs.Reverse)

	switch structs2.ReversePlatformType {
	case structs.ReverseType_Ceye:
		sub := utils.RandomStr(utils.AsciiLowercaseAndDigits, 8)
		urlStr = fmt.Sprintf("http://%s.%s/", sub, structs2.CeyeDomain)
	case structs.ReverseType_DnslogCN:
		dnslogCnRequest := structs2.DnslogCNGetDomainRequest
		resp, _, err := requests.DoRequest(dnslogCnRequest, false)
		if err != nil {
			return
		}
		content, _ := requests.GetRespBody(resp)
		urlStr = "http://" + string(content) + "/"
	default:
		return
	}

	u, _ := url.Parse(strings.TrimSpace(urlStr))

	reverse.Url = requests.ParseUrl(u)
	reverse.Domain = u.Hostname()
	reverse.Ip = u.Host
	reverse.IsDomainNameServer = false
	reverse.ReverseType = structs2.ReversePlatformType

	return
}

func reverseCheck(r *structs.Reverse, timeout int64) bool {
	switch r.ReverseType {
	case structs.ReverseType_Ceye:
		time.Sleep(time.Second * time.Duration(timeout))
		sub := strings.Split(r.Domain, ".")[0]
		urlStr := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s", structs2.CeyeApi, sub)
		req, _ := http.NewRequest("GET", urlStr, nil)
		resp, _, err := requests.DoRequest(req, false)
		if err != nil {
			return false
		}
		content, _ := requests.GetRespBody(resp)

		if !bytes.Contains(content, []byte(`"data": []`)) { // api返回结果不为空
			return true
		}
		return false
	case structs.ReverseType_DnslogCN:
		time.Sleep(time.Second * time.Duration(timeout))
		sub := strings.Split(r.Domain, ".")[0]
		resp, _, err := requests.DoRequest(structs2.DnslogCNGetRecordRequest, false)
		if err != nil {
			return false
		}
		content, _ := requests.GetRespBody(resp)

		if bytes.Contains(content, []byte(sub)) { // api返回结果存在域名
			return true
		}
		return false
	default:
		return false
	}

}

func PutReverse(reverse interface{}) {
	ReversePool.Put(reverse)
}
