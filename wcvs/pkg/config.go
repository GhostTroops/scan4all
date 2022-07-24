package pkg

import (
	myconfig "github.com/hktalent/scan4all/lib/util"
	"net/http"
	"net/url"

	"github.com/hktalent/scan4all/pkg/naabu/v2/pkg/runner"
	"golang.org/x/time/rate"
)

var Config ConfigStruct

type (
	ConfigStruct struct {
		Threads        int
		ReqRate        float64
		Verbosity      int
		DoPost         bool
		ContentType    string
		QuerySeperator string
		CacheBuster    string
		TimeOut        int
		DeclineCookies bool
		Force          bool
		UseHTTP        bool
		CLDiff         int
		HMDiff         int

		Recursivity int
		RecInclude  string
		RecExclude  []string
		RecDomains  []string
		RecLimit    int

		Urls       []string
		Cookies    []string
		Headers    []string
		Parameters []string
		Body       string

		OnlyTest string
		SkipTest string

		GeneratePath      string
		GenerateReport    bool
		EscapeJSON        bool
		GenerateCompleted bool

		ProxyCertPath string
		ProxyURL      string

		HeaderWordlist string
		QueryWordlist  string

		Limiter *rate.Limiter `json:"-"`
		Website WebsiteStruct `json:"-"`
	}

	WebsiteStruct struct {
		Headers      http.Header
		Body         string
		Cookies      []*http.Cookie
		Url          *url.URL
		UrlWOQueries string
		Queries      map[string]string
		StatusCode   int
		Cache        CacheStruct
		Domain       string
	}

	CacheStruct struct {
		CBwasFound     bool
		CBisParameter  bool
		CBisHeader     bool
		CBisCookie     bool
		CBisHTTPMethod bool
		CBName         string

		//HitMissVerbose bool
		//HitMissTime    bool

		NoCache       bool
		Indicator     string
		TimeIndicator bool
	}
)

func init() {
}

func ReadConfigFile() ConfigStruct {
	xConfig := myconfig.G_Options.(*runner.Options)
	nDebug := 0
	if xConfig.Verbose || xConfig.Debug {
		nDebug = 2
	}
	config := ConfigStruct{
		ReqRate:        float64(rate.Inf),
		Threads:        0,
		Recursivity:    0,
		Verbosity:      nDebug,
		DoPost:         false,
		ContentType:    "",
		QuerySeperator: "",
		CacheBuster:    "",
		TimeOut:        0,
		DeclineCookies: false,
		Urls:           nil,
		Cookies:        nil,
		Headers:        nil,
		Parameters:     nil,
		Body:           "",
		OnlyTest:       "",
		SkipTest:       "",
		ProxyCertPath:  "",
		ProxyURL:       "",
		HeaderWordlist: "",
		QueryWordlist:  "",
		Website: WebsiteStruct{
			Body:         "",
			Cookies:      nil,
			Url:          nil,
			UrlWOQueries: "",
			Queries:      nil,
			StatusCode:   0,
		},
	}

	return config
}
