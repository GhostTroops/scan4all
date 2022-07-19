package pkg

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
)

var (
	NoColor = ""
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Purple  = "\033[35m"
	Cyan    = "\033[36m"
	Gray    = "\033[37m"
	White   = "\033[97m"
)

func init() {
	if runtime.GOOS == "windows" {
		Reset = ""
		Red = ""
		Green = ""
		Yellow = ""
		Blue = ""
		Purple = ""
		Cyan = ""
		Gray = ""
		White = ""
	}
}

func removeColors(msg string) string {
	msg = strings.ReplaceAll(msg, Reset, "")
	msg = strings.ReplaceAll(msg, Red, "")
	msg = strings.ReplaceAll(msg, Green, "")
	msg = strings.ReplaceAll(msg, Yellow, "")
	msg = strings.ReplaceAll(msg, Blue, "")
	msg = strings.ReplaceAll(msg, Purple, "")
	msg = strings.ReplaceAll(msg, Cyan, "")
	msg = strings.ReplaceAll(msg, Gray, "")
	msg = strings.ReplaceAll(msg, White, "")
	msg = strings.Trim(msg, "\n")
	return msg
}

func PrintNewLine() {
	Print("\n", NoColor)
}

func PrintVerbose(msg string, color string, threshold int) {
	if color == Red {
		msg = color + "[ERR] " + Reset + msg
	} else if color == Yellow {
		msg = color + "[!] " + Reset + msg
	} else if color == Green {
		msg = color + "[+] " + Reset + msg
	} else if color == Cyan {
		msg = color + "[*] " + Reset + msg
	}

	if Config.Verbosity >= threshold {
		fmt.Print(msg)
	}
	log.Print(removeColors(msg))
}

func Print(msg string, color string) {
	PrintVerbose(msg, color, 0)
}

func PrintFatal(msg string) {
	Print(msg, Red)
	os.Exit(1)
}

func ReadLocalFile(path string, name string) []string {
	path = strings.TrimPrefix(path, "file:")

	if strings.HasPrefix(strings.ToLower(path), "file:") {
		PrintFatal("Please make sure that path: is lowercase")
	}

	w, err := ioutil.ReadFile(path)
	if err != nil {
		additional := ""
		if name == "header" {
			additional = "Use the flag \"-hw path/to/wordlist\" to specify the path to a header wordlist\n"
		} else if name == "parameter" {
			additional = "Use the flag \"-pw path/to/wordlist\" to specify the path to a parameter wordlist\n"
		}
		PrintFatal("The specified " + name + " file path " + path + " couldn't be found: " + err.Error() + "\n" + additional)
	}

	return strings.Split(string(w), "\n")
}

func setRequest(req *http.Request, doPost bool, cb string, cookie http.Cookie) {

	cache := Config.Website.Cache
	if cb != "" && cache.CBisParameter {
		var newUrl string
		newUrl, _ = addCachebusterParameter(req.URL.String(), cb)

		var err error
		req.URL, err = url.Parse(newUrl)
		if err != nil {
			msg := "Converting " + newUrl + " to URL:" + err.Error() + "\n"
			Print(msg, Red)
		}
	}

	setRequestHeaders(req, cb)
	//TODO config nötig oder nur config.Website.Cookies?
	setRequestCookies(req, cb, cookie)

	// Content-Type nur hinzufügen, wenn nicht schon vorher geschehen
	if doPost {
		if req.Header.Get("Content-Type") == "" && Config.ContentType != "" {
			req.Header.Add("Content-Type", Config.ContentType)
		}
	}
}

/* TODO wie bei requestCookies nur die erste occurance eines headers aufnehmen */
func setRequestHeaders(req *http.Request, cb string) {
	cache := Config.Website.Cache

	req.Header.Set("User-Agent", useragent)
	for _, h := range Config.Headers {
		h = strings.TrimSuffix(h, "\r")
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		} else if !strings.Contains(h, ":") {
			msg := "Specified header" + h + "doesn't contain a : and will be skipped"
			Print(msg, NoColor)
			continue
		} else {
			hSplitted := strings.SplitN(h, ":", 2)

			// is this header the cachebuster?
			if cb != "" && cache.CBisHeader && strings.EqualFold(hSplitted[0], cache.CBName) {
				req.Header.Set(cache.CBName, cb)
			}

			req.Header.Set(strings.TrimSpace(hSplitted[0]), strings.TrimSpace(hSplitted[1]))
		}
	}
}

/* */
func setRequestCookies(req *http.Request, cb string, cookie http.Cookie) {
	cache := Config.Website.Cache

	for _, c := range Config.Website.Cookies {
		// only add first occurence of a cookie to the request
		_, err := req.Cookie(c.Name)
		if err == http.ErrNoCookie {
			if cb != "" && cache.CBisCookie && c.Name == cache.CBName {
				c.Value = cb

				if c.Name == cookie.Name {
					msg := "Can't test cookie " + c.Name + " for Web Cache Poisoning, as it is used as Cachebuster\n"
					Print(msg, Yellow)
				}
			} else if c.Name == cookie.Name {
				c = &cookie
			}
			req.AddCookie(c)
		}
	}
}

/*	if rp.newCookie.Name != "" {
	if Config.Website.Cache.CBisCookie && strings.EqualFold(Config.Website.Cache.CBName, rp.newCookie.Name) {
		msg = "Can't test cookie " + rp.newCookie.Name + " for Web Cache Poisoning, as it is used as Cachebuster\n"
		Print(msg, Yellow)
	} else {
		removeCookie := http.Cookie
		req.AddCookie(&rp.newCookie)
	}
*/

func addCachebusterParameter(strUrl string, cb string) (string, string) {
	if cb == "" {
		cb = randInt()
	}
	if !strings.Contains(strUrl, "?") {
		strUrl += "?" + Config.CacheBuster + "=" + cb
	} else {
		strUrl += Config.QuerySeperator + Config.CacheBuster + "=" + cb
	}

	return strUrl, cb
}

/* Create a random long integer */
func randInt() string {
	min := 100000000000
	max := 999999999999
	result := min + rand.Intn(max-min)
	return strconv.Itoa(result)
}

func waitLimiter(identifier string) {
	err := Config.Limiter.Wait(context.Background())
	if err != nil {
		msg := identifier + " rate Wait: " + err.Error()
		Print(msg, Red)
	}
}

func searchBodyHeadersForString(cb string, body string, headers http.Header) bool {
	if strings.Contains(body, cb) {
		return true
	}
	for _, h := range headers {
		for _, v := range h {
			if strings.Contains(v, cb) {
				return true
			}
		}
	}
	return false
}

// check if cache was hit
func checkCacheHit(value string) bool {
	indicator := Config.Website.Cache.Indicator
	if strings.EqualFold("age", indicator) {
		value = strings.TrimSpace(value)
		if value != "0" {
			return true
		}
	} else if strings.EqualFold("x-iinfo", indicator) {
		if strings.EqualFold(value[22:23], "C") || strings.EqualFold(value[22:23], "V") {
			return true
		}
		// Cache Hit may have 0,>0 or >0,0 as value. Both responses are cached
	} else if strings.EqualFold("x-cache-hits", indicator) {
		for _, x := range strings.Split(indicator, ",") {
			x = strings.TrimSpace(x)
			if x != "0" {
				return true
			}
		}
		// Some Headers may have "miss,hit" or "hit,miss" as value. But both are cached responses.
	} else if strings.Contains(value, "hit") {
		return true
	}
	return false
}
