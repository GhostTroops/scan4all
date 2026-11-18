package metafiles

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/dimchansky/utfbom"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/retryabledns"
)

// loads Entries from hosts file if max is -1 it will load all entries to given hybrid map
func loadHostsFile(hm *hybrid.HybridMap, max int) error {
	osHostsFilePath := os.ExpandEnv(filepath.FromSlash(HostsFilePath))

	if env, isset := os.LookupEnv("HOSTS_PATH"); isset && len(env) > 0 {
		osHostsFilePath = os.ExpandEnv(filepath.FromSlash(env))
	}

	file, err := os.Open(osHostsFilePath)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	dnsDatas := make(map[string]retryabledns.DNSData)
	scanner := bufio.NewScanner(utfbom.SkipOnly(file))
	for scanner.Scan() {
		if max > 0 && len(dnsDatas) == MaxHostsEntires {
			break
		}
		ip, hosts := HandleHostLine(scanner.Text())
		if ip == "" || len(hosts) == 0 {
			continue
		}
		netIP := net.ParseIP(ip)
		isIPv4 := netIP.To4() != nil
		isIPv6 := netIP.To16() != nil

		for _, host := range hosts {
			dnsdata, ok := dnsDatas[host]
			if !ok {
				dnsdata = retryabledns.DNSData{Host: host}
			}
			if isIPv4 {
				dnsdata.A = append(dnsdata.A, ip)
			} else if isIPv6 {
				dnsdata.AAAA = append(dnsdata.AAAA, ip)
			}
			dnsDatas[host] = dnsdata
		}
	}
	for host, dnsdata := range dnsDatas {
		dnsdataBytes, _ := dnsdata.Marshal()
		_ = hm.Set(host, dnsdataBytes)
	}
	if len(dnsDatas) > 10000 && max < 0 {
		// this freeups memory when loading large hosts files
		// useful when loading all entries to hybrid storage
		debug.FreeOSMemory()
	}
	return nil
}

const CommentChar string = "#"

// HandleHostLine a hosts file line
func HandleHostLine(raw string) (ip string, hosts []string) {
	// ignore comment
	if IsComment(raw) {
		return
	}

	// trim comment
	if HasComment(raw) {
		commentSplit := strings.Split(raw, CommentChar)
		raw = commentSplit[0]
	}

	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return
	}

	// not a valid ip
	ip = fields[0]
	if net.ParseIP(ip) == nil {
		return
	}

	hosts = fields[1:]
	return
}

// IsComment check if the file is a comment
func IsComment(raw string) bool {
	return strings.HasPrefix(strings.TrimSpace(raw), CommentChar)
}

// HasComment check if the line has a comment
func HasComment(raw string) bool {
	return strings.Contains(raw, CommentChar)
}
