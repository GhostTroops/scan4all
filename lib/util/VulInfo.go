package util

type VulnInfo struct {
	Name         string
	VulID        []string
	Version      string
	Author       string
	VulDate      string
	References   []string
	AppName      string
	AppPowerLink string
	AppVersion   string
	VulType      string
	Description  string
	Category     string
	Dork         QueryDork
}

type QueryDork struct {
	Fofa    string
	Quake   string
	Zoomeye string
	Shodan  string
}
