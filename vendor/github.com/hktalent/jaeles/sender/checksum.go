package sender

import (
	"github.com/PuerkitoBio/goquery"
	"github.com/hktalent/jaeles/libs"
	"github.com/hktalent/jaeles/utils"
	"github.com/spf13/cast"
	"regexp"
	"sort"
	"strings"
)

func GenCheckSum(res *libs.Response) string {
	var checksum, scriptStructure string
	var domStructure, cssStructure, headerKeys, cookies []string

	contentLines := len(strings.Split(res.Body, "\n"))
	contentWords := len(strings.Split(res.Body, " "))

	// Verify the content type
	contentType := "text/html"
	title := "Blank-Title"

	// Header keys
	for _, header := range res.Headers {
		for k, v := range header {
			key := strings.ToLower(k)
			headerKeys = append(headerKeys, key)
			if strings.Contains(key, "content-type") {
				contentType = v
			}

			if strings.Contains(key, "set-cookie") {
				cookies = append(cookies, v)
			}

		}
	}
	sort.Strings(headerKeys)
	// Set-Cookie keys
	var cookieKeys []string
	if len(cookies) > 0 {
		for _, cookie := range cookies {
			if strings.Contains(cookie, "=") {
				cookieKey := strings.Split(cookie, "=")[0]
				cookieKeys = append(cookieKeys, cookieKey)
			}
		}
	}
	sort.Strings(cookieKeys)

	if strings.Contains(contentType, "html") {
		doc, _ := goquery.NewDocumentFromReader(strings.NewReader(res.Body))
		domStructure, cssStructure = GetDomCssList(doc)
		scriptStructure = GetScriptSrc(doc)
		title = GetTitle(doc)
	}

	format := []string{
		title,
		res.Status,
		contentType,
		cast.ToString(contentLines),
		cast.ToString(contentWords),
		strings.Join(domStructure, ","),
		strings.Join(cssStructure, ","),
		scriptStructure,
		strings.Join(headerKeys, ","),
		strings.Join(cookieKeys, ","),
	}

	checksum = utils.GenHash(strings.Join(format, ";;"))
	res.Checksum = checksum
	return checksum
}

// GetTitle get title of response
func GetTitle(doc *goquery.Document) string {
	var title string
	doc.Find("title").Each(func(i int, s *goquery.Selection) {
		title = strings.TrimSpace(s.Text())
	})
	if title == "" {
		title = "Blank Title"
	}

	// clean title if if have new line here
	if strings.Contains(title, "\n") {
		title = regexp.MustCompile(`[\t\r\n]+`).ReplaceAllString(strings.TrimSpace(title), "\n")
	}
	return title
}

// GetScriptSrc calculate Hash based on src in scripts
func GetScriptSrc(doc *goquery.Document) string {
	var result []string
	doc.Find("*").Each(func(i int, s *goquery.Selection) {
		tag := goquery.NodeName(s)
		result = append(result, tag)
		if tag == "script" {
			src, _ := s.Attr("src")
			if src != "" {
				result = append(result, src)
			}
		}
	})
	sort.Strings(result)
	return strings.Join(result, "-")
}

func GetDomCssList(doc *goquery.Document) ([]string, []string) {
	var queue []*goquery.Selection
	var domRes []string
	var cssRes []string
	queue = append(queue, doc.Selection)
	for len(queue) > 0 {
		curSel := queue[0]
		queue = queue[1:]
		if len(curSel.Nodes) == 0 {
			continue
		}

		for _, node := range curSel.Nodes {
			for _, item := range node.Attr {
				key := strings.ToLower(item.Key)
				if key == "class" || key == "style" {
					cssRes = append(cssRes, item.Val)
				}
			}
		}

		curSel.Contents().Each(func(i int, s *goquery.Selection) {
			nName := goquery.NodeName(s)
			if nName == "#text" {
				return
			}
			domRes = append(domRes, nName)
		})
		queue = append(queue, curSel.Children())
	}
	return domRes[1:], cssRes
}
