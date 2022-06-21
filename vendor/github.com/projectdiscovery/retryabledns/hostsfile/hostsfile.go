package hostsfile

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/stringsutil"
)

func Path() string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`%s\System32\Drivers\etc\hosts`, os.Getenv("SystemRoot"))
	}
	return "/etc/hosts"
}

func ParseDefault() (map[string][]string, error) {
	return Parse(Path())
}

func Parse(p string) (map[string][]string, error) {
	if !fileutil.FileExists(p) {
		return nil, errors.New("hosts file doesn't exist")
	}

	hostsFileCh, err := fileutil.ReadFile(p)
	if err != nil {
		return nil, err
	}

	items := make(map[string][]string)
	for line := range hostsFileCh {
		line = strings.TrimSpace(line)
		// skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// discard comment part
		if strings.Contains(line, "#") {
			line = stringsutil.Before(line, "#")
		}
		tokens := strings.Fields(line)
		if len(tokens) > 1 {
			ip := tokens[0]
			for _, hostname := range tokens[1:] {
				items[hostname] = append(items[hostname], ip)
			}
		}
	}
	return items, nil
}
