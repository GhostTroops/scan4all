package networkpolicy

import "regexp"

var DefaultSchemeAllowList = []string{
	"http",
	"https",
}

var schemePattern *regexp.Regexp

func init() {
	var err error
	schemePattern, err = regexp.Compile(`^[a-z0-9]+(://)?`)
	if err != nil {
		panic(err)
	}
}
