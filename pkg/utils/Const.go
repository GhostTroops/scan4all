package utils

import "regexp"

// 和 config.json 一致
const (
	Ipgs       = "ipgs"
	Ksubdomain = "ksubdomain"
	Httpx      = "httpx"
	Tlsx       = "tlsx"
	Nuclei     = "nuclei"
	Gopoc      = "gopoc"
	Filefuzz   = "filefuzz"
	Nmap       = "nmap"
	Masscan    = "masscan"
)

var (
	TrimXx = regexp.MustCompile(`^\*\.`)
)
