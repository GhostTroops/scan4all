package output

import (
	"github.com/boy-hack/ksubdomain/core"
	"github.com/boy-hack/ksubdomain/core/gologger"
	"github.com/boy-hack/ksubdomain/runner/result"
	"strings"
)

type ScreenOutput struct {
	windowsWidth int
	onlyDomain   bool
}

func NewScreenOutput(onlyDomain bool) (*ScreenOutput, error) {
	windowsWidth := core.GetWindowWith()
	s := new(ScreenOutput)
	s.windowsWidth = windowsWidth
	s.onlyDomain = onlyDomain
	return s, nil
}
func (s *ScreenOutput) WriteDomainResult(domain result.Result) error {
	var msg string
	if s.onlyDomain {
		msg = domain.Subdomain
	} else {
		var domains []string = []string{domain.Subdomain}
		for _, item := range domain.Answers {
			domains = append(domains, item)
		}
		msg = strings.Join(domains, " => ")
	}
	screenWidth := s.windowsWidth - len(msg) - 1
	if s.windowsWidth > 0 && screenWidth > 0 {
		gologger.Silentf("\r%s% *s\n", msg, screenWidth, "")
	} else {
		gologger.Silentf("\r%s\n", msg)
	}
	return nil
}
func (s *ScreenOutput) Close() {

}
