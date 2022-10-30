// +build !windows

package dnsutil

import (
	"bufio"
	"errors"
	"os"
	"strings"
)

func nameserver() (string, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		cols := strings.Fields(line)
		if len(cols) < 2 {
			continue
		}
		switch cols[0] {
		case "nameserver":
			return cols[1], nil
		}
	}
	return "", errors.New("nameserver: not found")
}
