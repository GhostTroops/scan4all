package pkg

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

func init() {

}

func GenerateHeaderString() string {
	headers := ""
	userAgent := useragent
	cache := Config.Website.Cache
	for i, c := range Config.Website.Cookies {
		if i == 0 {
			headers += "Cookie: "
		} else {
			headers += "; "
		}
		valToAdd := c.Value
		if cache.CBisCookie && c.Name == cache.CBName {
			valToAdd = randInt()
		}
		headers += c.Name + "=" + valToAdd
	}

	if headers != "" {
		headers += "\r\n"
	}

	headerSlice := Config.Headers
	if cache.CBisHeader {
		headerSlice = append(headerSlice, cache.CBName+": "+randInt())
	}

	for i, h := range headerSlice {
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
			hSplitted[0] = strings.TrimSpace(hSplitted[0])
			hSplitted[1] = strings.TrimSpace(hSplitted[1])

			// Only add header that has the same name as the cachebuster header, if it is the last header of the slice
			if cache.CBisHeader && strings.EqualFold(hSplitted[0], cache.CBName) && i+1 != len(headerSlice) {
				continue
			}

			headers += h + "\r\n"

			if strings.EqualFold(hSplitted[0], "User-Agent") {
				userAgent = hSplitted[1]
			}
		}
	}
	// if its the same, the useragent wasnt added yet
	if userAgent == useragent {
		headers += "User-Agent: " + useragent + "\r\n"
	}

	return headers
}

/* Run clte before tecl. Dont test for tecl if clte already works! */
func clte(path string, headers string) string {
	httpMethod := "POST"
	if Config.Website.Cache.CBisHTTPMethod {
		httpMethod = Config.Website.Cache.CBName
	}
	payload := fmt.Sprintf(""+
		"%s %s HTTP/1.1\r\n"+ //			 POST /about HTTP/1.1
		"Host: %s\r\n"+ //					 Host: example.com
		"%s"+ //							 *Additional Headers generated*
		"Transfer-Encoding: chunked\r\n"+ // Transfer-Encoding: chunked
		"Content-Length: 4\r\n"+ //			 Content-Length: 4
		"\r\n"+ //
		"1\r\n"+ //							 1
		"Z\r\n"+ //							 Z
		"Q"+ //								 Q
		"", httpMethod, path, Config.Website.Url.Host, headers)

	return payload
}

func tecl(path string, headers string) string {
	httpMethod := "POST"
	if Config.Website.Cache.CBisHTTPMethod {
		httpMethod = Config.Website.Cache.CBName
	}
	payload := fmt.Sprintf(""+
		"%s %s HTTP/1.1\r\n"+ //			 POST /about HTTP/1.1
		"Host: %s\r\n"+ //					 Host: example.com
		"%s"+ //							 *Additional Headers generated*
		"Transfer-Encoding: chunked\r\n"+ // Transfer-Encoding: chunked
		"Content-Length: 6\r\n"+ //			 Content-Length: 6
		"\r\n"+ //
		"0\r\n"+ //							 0
		"\r\n"+ //
		"X"+ //								 X
		"", httpMethod, path, Config.Website.Url.Host, headers)
	return payload
}

func clcl(path string, headers string) string {
	httpMethod := "POST"
	if Config.Website.Cache.CBisHTTPMethod {
		httpMethod = Config.Website.Cache.CBName
	}
	payload := fmt.Sprintf(""+
		"%s %s HTTP/1.1\r\n"+ //			 POST /about HTTP/1.1
		"Host: %s\r\n"+ //					 Host: example.com
		"%s"+ //							 *Additional Headers generated*
		"Content-Length: 10\r\n"+ // 		 Content-Length: 10
		"Content-Length: 11\r\n"+ //		 Content-Length: 11
		"\r\n"+ //
		"M\r\n"+ //							 M
		"1\r\n"+ //							 1
		"0\r\n"+ //							 0
		"X"+ //								 X
		"", httpMethod, path, Config.Website.Url.Host, headers)

	return payload
}

func clcl2(path string, headers string) string {
	httpMethod := "POST"
	if Config.Website.Cache.CBisHTTPMethod {
		httpMethod = Config.Website.Cache.CBName
	}
	payload := fmt.Sprintf(""+
		"%s %s HTTP/1.1\r\n"+ //			 POST /about HTTP/1.1
		"Host: %s\r\n"+ //					 Host: example.com
		"%s"+ //							 *Additional Headers generated*
		"Content-Length: 6\r\n"+ //			 Content-Length: 11
		"Content-Length: 4\r\n"+ //			 Content-Length: 10
		"\r\n"+ //
		"M\r\n"+ //							 M
		"1\r\n"+ //							 1
		"0\r\n"+ //							 0
		"X"+ //								 X
		"", httpMethod, path, Config.Website.Url.Host, headers)

	return payload
}

func httpRequestSmuggling(req string, result *reportResult, proxyUrl *url.URL) {
	/*
		dialer, err := proxy.SOCKS5("tcp", strings.TrimPrefix(Config.ProxyURL, "http://"), nil, nil)
		if err != nil {
			PrintFatal(err.Error())
		}
		Print("ads", NoColor)*/
	errorString := "httpRequestSmuggling"

	httpsUsed := false
	proxyUsed := false
	address := Config.Website.Domain
	address = strings.TrimSuffix(address, "/")

	if strings.HasPrefix(address, "https://") {
		httpsUsed = true
		address = strings.TrimPrefix(address, "https://")
		if !strings.Contains(address, ":") {
			address += ":443"
		}
	} else if strings.HasPrefix(address, "http://") {
		address = strings.TrimPrefix(address, "http://")
		if !strings.Contains(address, ":") {
			address += ":80"
		}
	} else {
		msg := "Request Smuggling: " + address + " doesn't has http:// or https:// as prefix\n"
		Print(msg, Yellow)
		result.HasError = true
		result.ErrorMessages = append(result.ErrorMessages, msg)
		return
	}

	if Config.ProxyCertPath != "" {
		//proxyUsed = true
		proxyUsed = false
	}

	timeOutCount := 0
	for i := 0; i < 3; i++ {
		var err error
		var connS *tls.Conn
		var conn net.Conn

		var resp string
		var msg string

		waitLimiter(fmt.Sprintf("%s %d", errorString, i))
		if proxyUsed {
			dialerP, err := proxy.FromURL(proxyUrl, proxy.Direct)
			/*dialerP, err := proxy.SOCKS5("tcp", proxyUrl.Host, nil, &net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 15 * time.Second,
			})*/
			if err != nil {
				msg = fmt.Sprintf("%s: proxy.FromURL: %s", errorString, err.Error())
				Print(msg+"\n", Red)
				result.HasError = true
				result.ErrorMessages = append(result.ErrorMessages, msg)
				return
			}
			conn, err = dialerP.Dial("tcp", address)

			if err != nil {
				msg = fmt.Sprintf("%s: dialerP.Dial: %s", errorString, err.Error())
				Print(msg+"\n", Red)
				result.HasError = true
				result.ErrorMessages = append(result.ErrorMessages, msg)
			}
		} else if httpsUsed {
			/* Das hat teilweise zu Errorn geführt ohne InsecureSkipVerify
			if tlsConfig == nil {
				tlsConfig = new(tls.Config)
			}
			*/
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
			}
			connS, err = tls.Dial("tcp", address, tlsConfig)

			if err != nil {
				msg = fmt.Sprintf("%s: tls.Dial: %s", errorString, err.Error())
				Print(msg+"\n", Red)
				result.HasError = true
				result.ErrorMessages = append(result.ErrorMessages, msg)
				return
			}
		} else {
			dialer := net.Dialer{Timeout: time.Duration(Config.TimeOut) * time.Second}
			conn, err = dialer.Dial("tcp", address)

			if err != nil {
				msg = fmt.Sprintf("%s: dialerP.Dial: %s", errorString, err.Error())
				Print(msg+"\n", Red)
				result.HasError = true
				result.ErrorMessages = append(result.ErrorMessages, msg)
				return
			}
		}

		err = nil
		if proxyUsed {
			defer conn.Close()

			fmt.Fprint(conn, req)
			conn.SetReadDeadline(time.Now().Add(time.Duration(Config.TimeOut) * time.Second))
			resp, err = bufio.NewReader(conn).ReadString('\n')
		} else if httpsUsed {
			defer connS.Close()

			fmt.Fprint(connS, req)
			connS.SetReadDeadline(time.Now().Add(time.Duration(Config.TimeOut) * time.Second))
			resp, err = bufio.NewReader(connS).ReadString('\n')
		} else {
			defer conn.Close()

			fmt.Fprint(conn, req)
			conn.SetReadDeadline(time.Now().Add(time.Duration(Config.TimeOut) * time.Second))
			resp, err = bufio.NewReader(conn).ReadString('\n')
		}

		if err != nil {
			msg = fmt.Sprintf("%s: bufio.NewReader.ReadString: %s", errorString, err.Error())
			Print(msg+"\n", Yellow)

			// Time out error is same for TLS and Conn. Both use net.Error.Timeout
			nerr, _ := err.(net.Error)
			if nerr != nil && nerr.Timeout() {
				timeOutCount++
				msg = fmt.Sprintf("(%d/3) timeouts to confirm Request Smuggling\n", i+1)
				Print(msg, Yellow)
				//TODO: Wenn timeout, dann noch ein normales request senden, welches nicht auch timeouten darf?
			} else {
				msg = "Aborting test because of: " + err.Error() + "\n"
				Print(msg, Yellow)
				result.HasError = true
				result.ErrorMessages = append(result.ErrorMessages, msg)
				return
			}
		} else {
			// When there isn't a timout this means that the Request Smuggling technique wasn't successful!
			// TODO: Print entfernen!
			if strings.Contains(resp, "500") {
				reason := "Server returned 500 Internal Server Error. It *may* be vulnerable to this Request Smuggling technique."
				fillRequest(result, reason, req, Config.Website.Url.String())
				msg = "Response:" + resp + reason + "\n"
				Print(msg, Green)
			} else {
				msg = "Response:" + resp + "Request didn't time out and therefore *likely* isn't vulnerable to this Request Smuggling technique.\n"
				PrintVerbose(msg, White, 2)
			}
			return
		}
	}

	if timeOutCount == 3 {
		msg := "The request timed out 3 times in a row. It *may* be vulnerable to this Request Smuggling technique."
		fillRequest(result, msg, req, Config.Website.Url.String())
		Print(msg+"\n", Green)
	}
}

func fillRequest(result *reportResult, reason string, req string, reqURL string) {
	result.Vulnerable = true
	var request reportRequest
	request.Reason = reason
	request.Request = req
	request.URL = reqURL
	result.Requests = append(result.Requests, request)
}
