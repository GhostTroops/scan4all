package winrm

import (
	"os"
)
import (
	"github.com/masterzen/winrm"
)

// https://pentestlab.blog/tag/winrm/
// nmap -p 5985 -sV 10.0.0.2 10.0.0.1
// https://www.hackingarticles.in/winrm-penetration-testing/
// port: wsman/WinRM service
// 5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
func WinrmAuth(host, user, pass string, port int) (result bool, err error) {
	result = false
	endpoint := winrm.NewEndpoint(host, port, false, false, nil, nil, nil, 0)
	client, err := winrm.NewClient(endpoint, user, pass)
	if err != nil {
		//log.Println("WinrmAuth ",err)
	}
	res, err := client.Run("echo ISOK", os.Stdout, os.Stderr)
	if res == 0 {
		result = true
	}
	return result, err
}
