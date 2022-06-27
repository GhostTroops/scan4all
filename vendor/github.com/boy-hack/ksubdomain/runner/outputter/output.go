package outputter

import (
	"github.com/boy-hack/ksubdomain/runner/result"
)

type Output interface {
	WriteDomainResult(domain result.Result) error
	Close()
}
