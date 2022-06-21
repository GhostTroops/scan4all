package fastdialer

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/dimchansky/utfbom"
)

func loadResolverFile() ([]string, error) {
	osResolversFilePath := os.ExpandEnv(filepath.FromSlash(ResolverFilePath))

	if env, isset := os.LookupEnv("RESOLVERS_PATH"); isset && len(env) > 0 {
		osResolversFilePath = os.ExpandEnv(filepath.FromSlash(env))
	}

	file, err := os.Open(osResolversFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var systemResolvers []string

	scanner := bufio.NewScanner(utfbom.SkipOnly(file))
	for scanner.Scan() {
		resolverIP := HandleResolverLine(scanner.Text())
		if resolverIP == "" {
			continue
		}
		systemResolvers = append(systemResolvers, net.JoinHostPort(resolverIP, "53"))
	}
	return systemResolvers, nil
}

// HandleLine a resolver file line
func HandleResolverLine(raw string) (ip string) {
	// ignore comment
	if IsComment(raw) {
		return
	}

	// trim comment
	if HasComment(raw) {
		commentSplit := strings.Split(raw, commentChar)
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
