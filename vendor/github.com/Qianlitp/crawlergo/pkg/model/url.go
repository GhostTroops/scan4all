package model

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/Qianlitp/crawlergo/pkg/tools/requests"
)

type URL struct {
	url.URL
}

func GetUrl(_url string, parentUrls ...URL) (*URL, error) {
	// 补充解析URL为完整格式
	var u URL
	_url, err := u.parse(_url, parentUrls...)
	if err != nil {
		return nil, err
	}

	if len(parentUrls) == 0 {
		_u, err := requests.UrlParse(_url)
		if err != nil {
			return nil, err
		}
		u = URL{*_u}
		if u.Path == "" {
			u.Path = "/"
		}
	} else {
		pUrl := parentUrls[0]
		_u, err := pUrl.Parse(_url)
		if err != nil {
			return nil, err
		}
		u = URL{*_u}
		if u.Path == "" {
			u.Path = "/"
		}
		//fmt.Println(_url, pUrl.String(), u.String())
	}

	fixPath := regexp.MustCompile("^/{2,}")

	if fixPath.MatchString(u.Path) {
		u.Path = fixPath.ReplaceAllString(u.Path, "/")
	}

	return &u, nil
}

/**
修复不完整的URL
*/
func (u *URL) parse(_url string, parentUrls ...URL) (string, error) {
	_url = strings.Trim(_url, " ")

	if len(_url) == 0 {
		return "", errors.New("invalid url, length 0")
	}
	// 替换掉多余的#
	if strings.Count(_url, "#") > 1 {
		_url = regexp.MustCompile(`#+`).ReplaceAllString(_url, "#")
	}

	// 没有父链接，直接退出
	if len(parentUrls) == 0 {
		return _url, nil
	}

	if strings.HasPrefix(_url, "http://") || strings.HasPrefix(_url, "https://") {
		return _url, nil
	} else if strings.HasPrefix(_url, "javascript:") {
		return "", errors.New("invalid url, javascript protocol")
	} else if strings.HasPrefix(_url, "mailto:") {
		return "", errors.New("invalid url, mailto protocol")
	}
	return _url, nil
}

func (u *URL) QueryMap() map[string]interface{} {
	queryMap := map[string]interface{}{}
	for key, value := range u.Query() {
		if len(value) == 1 {
			queryMap[key] = value[0]
		} else {
			queryMap[key] = value
		}
	}
	return queryMap
}

/**
返回去掉请求参数的URL
*/
func (u *URL) NoQueryUrl() string {
	return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
}

/**
返回不带Fragment的URL
*/
func (u *URL) NoFragmentUrl() string {
	return strings.Replace(u.String(), u.Fragment, "", -1)
}

func (u *URL) NoSchemeFragmentUrl() string {
	return fmt.Sprintf("://%s%s", u.Host, u.Path)
}

func (u *URL) NavigationUrl() string {
	return u.NoSchemeFragmentUrl()
}

/**
返回根域名

如 a.b.c.360.cn 返回 360.cn
*/
func (u *URL) RootDomain() string {
	domain := u.Hostname()
	suffix, icann := publicsuffix.PublicSuffix(strings.ToLower(domain))
	// 如果不是 icann 的域名，返回空字符串
	if !icann {
		return ""
	}
	i := len(domain) - len(suffix) - 1
	// 如果域名错误
	if i <= 0 {
		return ""
	}
	if domain[i] != '.' {
		return ""
	}
	return domain[1+strings.LastIndex(domain[:i], "."):]
}

/**
文件扩展名
*/
func (u *URL) FileName() string {
	parts := strings.Split(u.Path, `/`)
	lastPart := parts[len(parts)-1]
	if strings.Contains(lastPart, ".") {
		return lastPart
	} else {
		return ""
	}
}

/**
文件扩展名
*/
func (u *URL) FileExt() string {
	parts := path.Ext(u.Path)
	// 第一个字符会带有 "."
	if len(parts) > 0 {
		return strings.ToLower(parts[1:])
	}
	return parts
}

/**
回去上一级path, 如果当前就是root path，则返回空字符串
*/
func (u *URL) ParentPath() string {
	if u.Path == "/" {
		return ""
	} else if strings.HasSuffix(u.Path, "/") {
		if strings.Count(u.Path, "/") == 2 {
			return "/"
		}
		parts := strings.Split(u.Path, "/")
		parts = parts[:len(parts)-2]
		return strings.Join(parts, "/")
	} else {
		if strings.Count(u.Path, "/") == 1 {
			return "/"
		}
		parts := strings.Split(u.Path, "/")
		parts = parts[:len(parts)-1]
		return strings.Join(parts, "/")
	}
}
