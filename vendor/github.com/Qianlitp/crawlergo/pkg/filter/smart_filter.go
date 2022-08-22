package filter

import (
	"go/types"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/Qianlitp/crawlergo/pkg/config"
	"github.com/Qianlitp/crawlergo/pkg/logger"
	"github.com/Qianlitp/crawlergo/pkg/model"
	"github.com/Qianlitp/crawlergo/pkg/tools"

	mapset "github.com/deckarep/golang-set"
)

type SmartFilter struct {
	StrictMode                 bool
	SimpleFilter               SimpleFilter
	filterLocationSet          mapset.Set // 非逻辑型参数的位置记录 全局统一标记过滤
	filterParamKeyRepeatCount  sync.Map
	filterParamKeySingleValues sync.Map // 所有参数名重复数量统计
	filterPathParamKeySymbol   sync.Map // 某个path下的某个参数的值出现标记次数统计
	filterParamKeyAllValues    sync.Map
	filterPathParamEmptyValues sync.Map
	filterParentPathValues     sync.Map
	uniqueMarkedIds            mapset.Set // 标记后的唯一ID，用于去重
}

const (
	MaxParentPathCount         = 32 // 相对于上一级目录，本级path目录的数量修正最大值
	MaxParamKeySingleCount     = 8  // 某个URL参数名重复修正最大值
	MaxParamKeyAllCount        = 10 // 本轮所有URL中某个参数名的重复修正最大值
	MaxPathParamEmptyCount     = 10 // 某个path下的参数值为空，参数名个数修正最大值
	MaxPathParamKeySymbolCount = 5  // 某个Path下的某个参数的标记数量超过此值，则该参数被全局标记
)

const (
	CustomValueMark    = "{{Crawlergo}}"
	FixParamRepeatMark = "{{fix_param}}"
	FixPathMark        = "{{fix_path}}"
	TooLongMark        = "{{long}}"
	NumberMark         = "{{number}}"
	ChineseMark        = "{{chinese}}"
	UpperMark          = "{{upper}}"
	LowerMark          = "{{lower}}"
	UrlEncodeMark      = "{{urlencode}}"
	UnicodeMark        = "{{unicode}}"
	BoolMark           = "{{bool}}"
	ListMark           = "{{list}}"
	TimeMark           = "{{time}}"
	MixAlphaNumMark    = "{{mix_alpha_num}}"
	MixSymbolMark      = "{{mix_symbol}}"
	MixNumMark         = "{{mix_num}}"
	NoLowerAlphaMark   = "{{no_lower}}"
	MixStringMark      = "{{mix_str}}"
)

var chineseRegex = regexp.MustCompile("[\u4e00-\u9fa5]+")
var urlencodeRegex = regexp.MustCompile("(?:%[A-Fa-f0-9]{2,6})+")
var unicodeRegex = regexp.MustCompile(`(?:\\u\w{4})+`)
var onlyAlphaRegex = regexp.MustCompile("^[a-zA-Z]+$")
var onlyAlphaUpperRegex = regexp.MustCompile("^[A-Z]+$")
var alphaUpperRegex = regexp.MustCompile("[A-Z]+")
var alphaLowerRegex = regexp.MustCompile("[a-z]+")
var replaceNumRegex = regexp.MustCompile(`[0-9]+\.[0-9]+|\d+`)
var onlyNumberRegex = regexp.MustCompile(`^[0-9]+$`)
var numberRegex = regexp.MustCompile(`[0-9]+`)
var OneNumberRegex = regexp.MustCompile(`[0-9]`)
var numSymbolRegex = regexp.MustCompile(`\.|_|-`)
var timeSymbolRegex = regexp.MustCompile(`-|:|\s`)
var onlyAlphaNumRegex = regexp.MustCompile(`^[0-9a-zA-Z]+$`)
var markedStringRegex = regexp.MustCompile(`^{{.+}}$`)
var htmlReplaceRegex = regexp.MustCompile(`\.shtml|\.html|\.htm`)

func (s *SmartFilter) Init() {
	s.filterLocationSet = mapset.NewSet()
	s.filterParamKeyRepeatCount = sync.Map{}
	s.filterParamKeySingleValues = sync.Map{}
	s.filterPathParamKeySymbol = sync.Map{}
	s.filterParamKeyAllValues = sync.Map{}
	s.filterPathParamEmptyValues = sync.Map{}
	s.filterParentPathValues = sync.Map{}
	s.uniqueMarkedIds = mapset.NewSet()
}

/**
智能去重
可选严格模式

需要过滤则返回 true
*/
func (s *SmartFilter) DoFilter(req *model.Request) bool {
	// 首先过滤掉静态资源、基础的去重、过滤其它的域名
	if s.SimpleFilter.DoFilter(req) {
		logger.Logger.Debugf("filter req by simplefilter: " + req.URL.RequestURI())
		return true
	}

	req.Filter.FragmentID = s.calcFragmentID(req.URL.Fragment)

	// 标记
	if req.Method == config.GET || req.Method == config.DELETE || req.Method == config.HEAD || req.Method == config.OPTIONS {
		s.getMark(req)
		s.repeatCountStatistic(req)
	} else if req.Method == config.POST || req.Method == config.PUT {
		s.postMark(req)
	} else {
		logger.Logger.Debug("dont support such method: " + req.Method)
	}

	// 对标记后的请求进行去重
	uniqueId := req.Filter.UniqueId
	if s.uniqueMarkedIds.Contains(uniqueId) {
		logger.Logger.Debugf("filter req by uniqueMarkedIds 1: " + req.URL.RequestURI())
		return true
	}

	// 全局数值型参数标记
	s.globalFilterLocationMark(req)

	// 接下来对标记的GET请求进行去重
	if req.Method == config.GET || req.Method == config.DELETE || req.Method == config.HEAD || req.Method == config.OPTIONS {
		// 对超过阈值的GET请求进行标记
		s.overCountMark(req)

		// 重新计算 QueryMapId
		req.Filter.QueryMapId = getParamMapID(req.Filter.MarkedQueryMap)
		// 重新计算 PathId
		req.Filter.PathId = getPathID(req.Filter.MarkedPath)
	} else {
		// 重新计算 PostDataId
		req.Filter.PostDataId = getParamMapID(req.Filter.MarkedPostDataMap)
	}

	// 重新计算请求唯一ID
	req.Filter.UniqueId = getMarkedUniqueID(req)

	// 新的ID再次去重
	newUniqueId := req.Filter.UniqueId
	if s.uniqueMarkedIds.Contains(newUniqueId) {
		logger.Logger.Debugf("filter req by uniqueMarkedIds 2: " + req.URL.RequestURI())
		return true
	}

	// 添加到结果集中
	s.uniqueMarkedIds.Add(newUniqueId)
	return false
}

/**
Query的Map对象会自动解码，所以对RawQuery进行预先的标记
*/
func (s *SmartFilter) preQueryMark(rawQuery string) string {
	if chineseRegex.MatchString(rawQuery) {
		return chineseRegex.ReplaceAllString(rawQuery, ChineseMark)
	} else if urlencodeRegex.MatchString(rawQuery) {
		return urlencodeRegex.ReplaceAllString(rawQuery, UrlEncodeMark)
	} else if unicodeRegex.MatchString(rawQuery) {
		return unicodeRegex.ReplaceAllString(rawQuery, UnicodeMark)
	}
	return rawQuery
}

/**
对GET请求的参数和路径进行标记
*/
func (s *SmartFilter) getMark(req *model.Request) {
	// 首先是解码前的预先替换
	todoURL := *(req.URL)
	todoURL.RawQuery = s.preQueryMark(todoURL.RawQuery)

	// 依次打标记
	queryMap := todoURL.QueryMap()
	queryMap = markParamName(queryMap)
	queryMap = s.markParamValue(queryMap, *req)
	markedPath := MarkPath(todoURL.Path)

	// 计算唯一的ID
	var queryKeyID string
	var queryMapID string
	if len(queryMap) != 0 {
		queryKeyID = getKeysID(queryMap)
		queryMapID = getParamMapID(queryMap)
	} else {
		queryKeyID = ""
		queryMapID = ""
	}
	pathID := getPathID(markedPath)

	req.Filter.MarkedQueryMap = queryMap
	req.Filter.QueryKeysId = queryKeyID
	req.Filter.QueryMapId = queryMapID
	req.Filter.MarkedPath = markedPath
	req.Filter.PathId = pathID

	// 最后计算标记后的唯一请求ID
	req.Filter.UniqueId = getMarkedUniqueID(req)
}

/**
对POST请求的参数和路径进行标记
*/
func (s *SmartFilter) postMark(req *model.Request) {
	postDataMap := req.PostDataMap()

	postDataMap = markParamName(postDataMap)
	postDataMap = s.markParamValue(postDataMap, *req)
	markedPath := MarkPath(req.URL.Path)

	// 计算唯一的ID
	var postDataMapID string
	if len(postDataMap) != 0 {
		postDataMapID = getParamMapID(postDataMap)
	} else {
		postDataMapID = ""
	}
	pathID := getPathID(markedPath)

	req.Filter.MarkedPostDataMap = postDataMap
	req.Filter.PostDataId = postDataMapID
	req.Filter.MarkedPath = markedPath
	req.Filter.PathId = pathID

	// 最后计算标记后的唯一请求ID
	req.Filter.UniqueId = getMarkedUniqueID(req)
}

/**
标记参数名
*/
func markParamName(paramMap map[string]interface{}) map[string]interface{} {
	markedParamMap := map[string]interface{}{}
	for key, value := range paramMap {
		// 纯字母不处理
		if onlyAlphaRegex.MatchString(key) {
			markedParamMap[key] = value
			// 参数名过长
		} else if len(key) >= 32 {
			markedParamMap[TooLongMark] = value
			// 替换掉数字
		} else {
			key = replaceNumRegex.ReplaceAllString(key, NumberMark)
			markedParamMap[key] = value
		}
	}
	return markedParamMap
}

/**
标记参数值
*/
func (s *SmartFilter) markParamValue(paramMap map[string]interface{}, req model.Request) map[string]interface{} {
	markedParamMap := map[string]interface{}{}
	for key, value := range paramMap {
		switch value.(type) {
		case bool:
			markedParamMap[key] = BoolMark
			continue
		case types.Slice:
			markedParamMap[key] = ListMark
			continue
		case float64:
			markedParamMap[key] = NumberMark
			continue
		}
		// 只处理string类型
		valueStr, ok := value.(string)
		if !ok {
			continue
		}
		// Crawlergo 为特定字符，说明此参数位置为数值型，非逻辑型，记录下此参数，全局过滤
		if strings.Contains(valueStr, "Crawlergo") {
			name := req.URL.Hostname() + req.URL.Path + req.Method + key
			s.filterLocationSet.Add(name)
			markedParamMap[key] = CustomValueMark
			// 全大写字母
		} else if onlyAlphaUpperRegex.MatchString(valueStr) {
			markedParamMap[key] = UpperMark
			// 参数值长度大于等于16
		} else if len(valueStr) >= 16 {
			markedParamMap[key] = TooLongMark
			// 均为数字和一些符号组成
		} else if onlyNumberRegex.MatchString(valueStr) || onlyNumberRegex.MatchString(numSymbolRegex.ReplaceAllString(valueStr, "")) {
			markedParamMap[key] = NumberMark
			// 存在中文
		} else if chineseRegex.MatchString(valueStr) {
			markedParamMap[key] = ChineseMark
			// urlencode
		} else if urlencodeRegex.MatchString(valueStr) {
			markedParamMap[key] = UrlEncodeMark
			// unicode
		} else if unicodeRegex.MatchString(valueStr) {
			markedParamMap[key] = UnicodeMark
			// 时间
		} else if onlyNumberRegex.MatchString(timeSymbolRegex.ReplaceAllString(valueStr, "")) {
			markedParamMap[key] = TimeMark
			// 字母加数字
		} else if onlyAlphaNumRegex.MatchString(valueStr) && numberRegex.MatchString(valueStr) {
			markedParamMap[key] = MixAlphaNumMark
			// 含有一些特殊符号
		} else if hasSpecialSymbol(valueStr) {
			markedParamMap[key] = MixSymbolMark
			// 数字出现的次数超过3，视为数值型参数
		} else if b := OneNumberRegex.ReplaceAllString(valueStr, "0"); strings.Count(b, "0") >= 3 {
			markedParamMap[key] = MixNumMark
			// 严格模式
		} else if s.StrictMode {
			// 无小写字母
			if !alphaLowerRegex.MatchString(valueStr) {
				markedParamMap[key] = NoLowerAlphaMark
				// 常见的值一般为 大写字母、小写字母、数字、下划线的任意组合，组合类型超过三种则视为伪静态
			} else {
				count := 0
				if alphaLowerRegex.MatchString(valueStr) {
					count += 1
				}
				if alphaUpperRegex.MatchString(valueStr) {
					count += 1
				}
				if numberRegex.MatchString(valueStr) {
					count += 1
				}
				if strings.Contains(valueStr, "_") || strings.Contains(valueStr, "-") {
					count += 1
				}
				if count >= 3 {
					markedParamMap[key] = MixStringMark
				}
			}
		} else {
			markedParamMap[key] = value
		}
	}
	return markedParamMap
}

/**
标记路径
*/
func MarkPath(path string) string {
	pathParts := strings.Split(path, "/")
	for index, part := range pathParts {
		if len(part) >= 32 {
			pathParts[index] = TooLongMark
		} else if onlyNumberRegex.MatchString(numSymbolRegex.ReplaceAllString(part, "")) {
			pathParts[index] = NumberMark
		} else if strings.HasSuffix(part, ".html") || strings.HasSuffix(part, ".htm") || strings.HasSuffix(part, ".shtml") {
			part = htmlReplaceRegex.ReplaceAllString(part, "")
			// 大写、小写、数字混合
			if numberRegex.MatchString(part) && alphaUpperRegex.MatchString(part) && alphaLowerRegex.MatchString(part) {
				pathParts[index] = MixAlphaNumMark
				// 纯数字
			} else if b := numSymbolRegex.ReplaceAllString(part, ""); onlyNumberRegex.MatchString(b) {
				pathParts[index] = NumberMark
			}
			// 含有特殊符号
		} else if hasSpecialSymbol(part) {
			pathParts[index] = MixSymbolMark
		} else if chineseRegex.MatchString(part) {
			pathParts[index] = ChineseMark
		} else if unicodeRegex.MatchString(part) {
			pathParts[index] = UnicodeMark
		} else if onlyAlphaUpperRegex.MatchString(part) {
			pathParts[index] = UpperMark
			// 均为数字和一些符号组成
		} else if b := numSymbolRegex.ReplaceAllString(part, ""); onlyNumberRegex.MatchString(b) {
			pathParts[index] = NumberMark
			// 数字出现的次数超过3，视为伪静态path
		} else if b := OneNumberRegex.ReplaceAllString(part, "0"); strings.Count(b, "0") > 3 {
			pathParts[index] = MixNumMark
		}
	}
	newPath := strings.Join(pathParts, "/")
	return newPath
}

/**
全局数值型参数过滤
*/
func (s *SmartFilter) globalFilterLocationMark(req *model.Request) {
	name := req.URL.Hostname() + req.URL.Path + req.Method
	if req.Method == config.GET || req.Method == config.DELETE || req.Method == config.HEAD || req.Method == config.OPTIONS {
		for key := range req.Filter.MarkedQueryMap {
			name += key
			if s.filterLocationSet.Contains(name) {
				req.Filter.MarkedQueryMap[key] = CustomValueMark
			}
		}
	} else if req.Method == config.POST || req.Method == config.PUT {
		for key := range req.Filter.MarkedPostDataMap {
			name += key
			if s.filterLocationSet.Contains(name) {
				req.Filter.MarkedPostDataMap[key] = CustomValueMark
			}
		}
	}
}

/**
进行全局重复参数名、参数值、路径的统计标记
之后对超过阈值的部分再次打标记
*/
func (s *SmartFilter) repeatCountStatistic(req *model.Request) {
	queryKeyId := req.Filter.QueryKeysId
	pathId := req.Filter.PathId
	if queryKeyId != "" {
		// 所有参数名重复数量统计
		if v, ok := s.filterParamKeyRepeatCount.Load(queryKeyId); ok {
			s.filterParamKeyRepeatCount.Store(queryKeyId, v.(int)+1)
		} else {
			s.filterParamKeyRepeatCount.Store(queryKeyId, 1)
		}

		for key, value := range req.Filter.MarkedQueryMap {
			// 某个URL的所有参数名重复数量统计
			paramQueryKey := queryKeyId + key

			if set, ok := s.filterParamKeySingleValues.Load(paramQueryKey); ok {
				set := set.(mapset.Set)
				set.Add(value)
			} else {
				s.filterParamKeySingleValues.Store(paramQueryKey, mapset.NewSet(value))
			}

			//本轮所有URL中某个参数重复数量统计
			if _, ok := s.filterParamKeyAllValues.Load(key); !ok {
				s.filterParamKeyAllValues.Store(key, mapset.NewSet(value))
			} else {
				if v, ok := s.filterParamKeyAllValues.Load(key); ok {
					set := v.(mapset.Set)
					if !set.Contains(value) {
						set.Add(value)
					}
				}
			}

			// 如果参数值为空，统计该PATH下的空值参数名个数
			if value == "" {
				if _, ok := s.filterPathParamEmptyValues.Load(pathId); !ok {
					s.filterPathParamEmptyValues.Store(pathId, mapset.NewSet(key))
				} else {
					if v, ok := s.filterPathParamEmptyValues.Load(pathId); ok {
						set := v.(mapset.Set)
						if !set.Contains(key) {
							set.Add(key)
						}
					}
				}
			}

			pathIdKey := pathId + key
			// 某path下的参数值去重标记出现次数统计
			if v, ok := s.filterPathParamKeySymbol.Load(pathIdKey); ok {
				if markedStringRegex.MatchString(value.(string)) {
					s.filterPathParamKeySymbol.Store(pathIdKey, v.(int)+1)
				}
			} else {
				s.filterPathParamKeySymbol.Store(pathIdKey, 1)
			}

		}
	}

	// 相对于上一级目录，本级path目录的数量统计，存在文件后缀的情况下，放行常见脚本后缀
	if req.URL.ParentPath() == "" || inCommonScriptSuffix(req.URL.FileExt()) {
		return
	}

	//
	parentPathId := tools.StrMd5(req.URL.ParentPath())
	currentPath := strings.Replace(req.Filter.MarkedPath, req.URL.ParentPath(), "", -1)
	if _, ok := s.filterParentPathValues.Load(parentPathId); !ok {
		s.filterParentPathValues.Store(parentPathId, mapset.NewSet(currentPath))
	} else {
		if v, ok := s.filterParentPathValues.Load(parentPathId); ok {
			set := v.(mapset.Set)
			if !set.Contains(currentPath) {
				set.Add(currentPath)
			}
		}
	}
}

/**
对重复统计之后，超过阈值的部分再次打标记
*/
func (s *SmartFilter) overCountMark(req *model.Request) {
	queryKeyId := req.Filter.QueryKeysId
	pathId := req.Filter.PathId
	// 参数不为空，
	if req.Filter.QueryKeysId != "" {
		// 某个URL的所有参数名重复数量超过阈值 且该参数有超过三个不同的值 则打标记
		if v, ok := s.filterParamKeyRepeatCount.Load(queryKeyId); ok && v.(int) > MaxParamKeySingleCount {
			for key := range req.Filter.MarkedQueryMap {
				paramQueryKey := queryKeyId + key
				if set, ok := s.filterParamKeySingleValues.Load(paramQueryKey); ok {
					set := set.(mapset.Set)
					if set.Cardinality() > 3 {
						req.Filter.MarkedQueryMap[key] = FixParamRepeatMark
					}
				}
			}
		}

		for key := range req.Filter.MarkedQueryMap {
			// 所有URL中，某个参数不同的值出现次数超过阈值，打标记去重
			if paramKeySet, ok := s.filterParamKeyAllValues.Load(key); ok {
				paramKeySet := paramKeySet.(mapset.Set)
				if paramKeySet.Cardinality() > MaxParamKeyAllCount {
					req.Filter.MarkedQueryMap[key] = FixParamRepeatMark
				}
			}

			pathIdKey := pathId + key
			// 某个PATH的GET参数值去重标记出现次数超过阈值，则对该PATH的该参数进行全局标记
			if v, ok := s.filterPathParamKeySymbol.Load(pathIdKey); ok && v.(int) > MaxPathParamKeySymbolCount {
				req.Filter.MarkedQueryMap[key] = FixParamRepeatMark
			}
		}

		// 处理某个path下空参数值的参数个数超过阈值 如伪静态： http://bang.360.cn/?chu_xiu
		if v, ok := s.filterPathParamEmptyValues.Load(pathId); ok {
			set := v.(mapset.Set)
			if set.Cardinality() > MaxPathParamEmptyCount {
				newMarkerQueryMap := map[string]interface{}{}
				for key, value := range req.Filter.MarkedQueryMap {
					if value == "" {
						newMarkerQueryMap[FixParamRepeatMark] = ""
					} else {
						newMarkerQueryMap[key] = value
					}
				}
				req.Filter.MarkedQueryMap = newMarkerQueryMap
			}
		}
	}

	// 处理本级path的伪静态
	if req.URL.ParentPath() == "" || inCommonScriptSuffix(req.URL.FileExt()) {
		return
	}
	parentPathId := tools.StrMd5(req.URL.ParentPath())
	if set, ok := s.filterParentPathValues.Load(parentPathId); ok {
		set := set.(mapset.Set)
		if set.Cardinality() > MaxParentPathCount {
			if strings.HasSuffix(req.URL.ParentPath(), "/") {
				req.Filter.MarkedPath = req.URL.ParentPath() + FixPathMark
			} else {
				req.Filter.MarkedPath = req.URL.ParentPath() + "/" + FixPathMark
			}
		}
	}
}

// calcFragmentID 计算 fragment 唯一值，如果 fragment 的格式为 url path
func (s *SmartFilter) calcFragmentID(fragment string) string {
	if fragment == "" || !strings.HasPrefix(fragment, "/") {
		return ""
	}
	fakeUrl, err := model.GetUrl(fragment)
	if err != nil {
		logger.Logger.Error("cannot calculate url fragment: ", err)
		return ""
	}
	// XXX: discuss https://github.com/Qianlitp/crawlergo/issues/100
	fakeReq := model.GetRequest(config.GET, fakeUrl)
	s.getMark(&fakeReq)
	// s.repeatCountStatistic(&fakeReq)
	return fakeReq.Filter.UniqueId
}

/**
计算标记后的唯一请求ID
*/
func getMarkedUniqueID(req *model.Request) string {
	var paramId string
	if req.Method == config.GET || req.Method == config.DELETE || req.Method == config.HEAD || req.Method == config.OPTIONS {
		paramId = req.Filter.QueryMapId
	} else {
		paramId = req.Filter.PostDataId
	}

	uniqueStr := req.Method + paramId + req.Filter.PathId + req.URL.Host + req.Filter.FragmentID
	if req.RedirectionFlag {
		uniqueStr += "Redirection"
	}
	if req.URL.Path == "/" && req.URL.RawQuery == "" && req.URL.Scheme == "https" {
		uniqueStr += "https"
	}

	return tools.StrMd5(uniqueStr)
}

/**
计算请求参数的key标记后的唯一ID
*/
func getKeysID(dataMap map[string]interface{}) string {
	var keys []string
	var idStr string
	for key := range dataMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		idStr += key
	}
	return tools.StrMd5(idStr)
}

/**
计算请求参数标记后的唯一ID
*/
func getParamMapID(dataMap map[string]interface{}) string {
	var keys []string
	var idStr string
	var markReplaceRegex = regexp.MustCompile(`{{.+}}`)
	for key := range dataMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := dataMap[key]
		idStr += key
		if value, ok := value.(string); ok {
			idStr += markReplaceRegex.ReplaceAllString(value, "{{mark}}")
		}
	}
	return tools.StrMd5(idStr)
}

/**
计算PATH标记后的唯一ID
*/
func getPathID(path string) string {
	return tools.StrMd5(path)
}

/**
判断字符串中是否存在以下特殊符号
*/
func hasSpecialSymbol(str string) bool {
	symbolList := []string{"{", "}", " ", "|", "#", "@", "$", "*", ",", "<", ">", "/", "?", "\\", "+", "="}
	for _, sym := range symbolList {
		if strings.Contains(str, sym) {
			return true
		}
	}
	return false
}

func inCommonScriptSuffix(suffix string) bool {
	return config.ScriptSuffixSet.Contains(suffix)
}
