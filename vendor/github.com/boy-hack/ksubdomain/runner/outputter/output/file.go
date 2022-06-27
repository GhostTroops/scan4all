package output

import (
	"github.com/boy-hack/ksubdomain/runner/result"
	"os"
	"strings"
)

type FileOutPut struct {
	output     *os.File
	onlyDomain bool
}

func NewFileOutput(filename string, onlyDomain bool) (*FileOutPut, error) {
	output, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
	if err != nil {
		return nil, err
	}
	f := new(FileOutPut)
	f.output = output
	f.onlyDomain = onlyDomain
	return f, err
}
func (f *FileOutPut) WriteDomainResult(domain result.Result) error {
	var msg string
	if f.onlyDomain {
		msg = domain.Subdomain
	} else {
		var domains []string = []string{domain.Subdomain}
		for _, item := range domain.Answers {
			domains = append(domains, item)
		}
		msg = strings.Join(domains, "=>")
	}
	_, err := f.output.WriteString(msg + "\n")
	return err
}
func (f *FileOutPut) Close() {
	f.output.Close()
}
