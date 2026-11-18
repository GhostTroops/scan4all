package fastdialer

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dimchansky/utfbom"
	"github.com/projectdiscovery/fastdialer/fastdialer/metafiles"
	"github.com/projectdiscovery/utils/env"
)

var (
	// MaxResolverEntries limits the number of resolver entries parsed from
	// resolver file.
	//
	// -1 means no limit.
	//
	// Deprecated: Use [DefaultMaxResolverEntries] instead. Adjust via [Options].
	MaxResolverEntries = 4096
)

// ResolverConfig captures nameservers plus search-domain semantics from
// resolv.conf(5).
type ResolverConfig struct {
	// Resolvers are the list of nameservers.
	Resolvers []string

	// SearchDomains are the search domains.
	SearchDomains []string

	// Ndots enforces the resolv.conf(5) ndots: threshold for treating a name
	// as absolute before search domains are appended (see
	// https://man7.org/linux/man-pages/man5/resolv.conf.5.html).
	Ndots int
}

func loadResolverFile(opt Options) (*ResolverConfig, error) {
	osResolversFilePath := os.ExpandEnv(filepath.FromSlash(ResolverFilePath))

	maxResolverEntries := opt.MaxResolverEntries
	if maxResolverEntries == 0 {
		maxResolverEntries = env.GetEnvOrDefault("MAX_RESOLVERS", DefaultMaxResolverEntries)
	}

	if env, isset := os.LookupEnv("RESOLVERS_PATH"); isset && len(env) > 0 {
		osResolversFilePath = os.ExpandEnv(filepath.FromSlash(env))
	}

	file, err := os.Open(osResolversFilePath)
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = file.Close()
	}()

	config := &ResolverConfig{Ndots: opt.Ndots}
	scanner := bufio.NewScanner(utfbom.SkipOnly(file))

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if metafiles.IsComment(line) {
			continue
		}

		if metafiles.HasComment(line) {
			commentSplit := strings.Split(line, metafiles.CommentChar)
			line = commentSplit[0]
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "nameserver":
			if maxResolverEntries != -1 && len(config.Resolvers) >= maxResolverEntries {
				continue
			}

			resolverIP := HandleResolverLine(line)
			if resolverIP == "" {
				continue
			}

			config.Resolvers = append(config.Resolvers, net.JoinHostPort(resolverIP, "53"))
		case "search":
			if len(fields) > 1 {
				config.SearchDomains = append(config.SearchDomains, fields[1:]...)
			}
		case "domain":
			// per resolv.conf(5), domain is used when search is absent
			if len(config.SearchDomains) == 0 && len(fields) > 1 {
				config.SearchDomains = append(config.SearchDomains, fields[1])
			}
		case "options":
			for _, opt := range fields[1:] {
				if after, ok := strings.CutPrefix(opt, "ndots:"); ok {
					value := after
					if nd, err := strconv.Atoi(value); err == nil && nd > 0 {
						config.Ndots = nd
					}
				}
			}
		}
	}

	config.SearchDomains = dedupeStrings(config.SearchDomains)

	return config, nil
}

// HandleLine a resolver file line
func HandleResolverLine(raw string) (ip string) {
	// ignore comment
	if metafiles.IsComment(raw) {
		return
	}

	// trim comment
	if metafiles.HasComment(raw) {
		commentSplit := strings.Split(raw, metafiles.CommentChar)
		raw = commentSplit[0]
	}

	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return
	}

	nameserverPrefix := fields[0]
	if nameserverPrefix != "nameserver" {
		return
	}

	ip = fields[1]
	if net.ParseIP(ip) == nil {
		return
	}

	return ip
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))

	for _, v := range values {
		if v == "" {
			continue
		}

		if _, ok := seen[v]; ok {
			continue
		}

		seen[v] = struct{}{}
		out = append(out, v)
	}

	return out
}
