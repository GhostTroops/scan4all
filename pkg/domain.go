package pkg

import (
	"crypto/tls"
)

// get ssl info DNS
func GetSSLDNS(s string) (aRst []string, err1 error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", s+":443", conf)
	if err != nil {
		err1 = err
		return aRst, err1
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		for _, x := range cert.DNSNames {
			aRst = append(aRst, x)
		}
		//fmt.Print(cert.Issuer)
		//fmt.Print("\nSubject: ")
		//fmt.Print(cert.Subject)
		//fmt.Print("\nSerial Number: ")
		//fmt.Print(cert.SerialNumber)
		//fmt.Print("\nVersion: ")
		//fmt.Print(cert.Version)
		//fmt.Print("\nNot Before: ")
		//fmt.Print(cert.NotBefore)
		//fmt.Print("\nNot After: ")
		//fmt.Print(cert.NotAfter)
		//fmt.Print("\nEmail Addresses: ")
		//fmt.Print(cert.EmailAddresses)
		//fmt.Print("\nIP Addresses: ")
		//fmt.Print(cert.IPAddresses)
		//fmt.Print("\nPermitted DNS Domains: ")
		//fmt.Print(cert.PermittedDNSDomains)
		//fmt.Print("\nExcluded DNS Domains: ")
		//fmt.Print(cert.ExcludedDNSDomains)
		//fmt.Print("\nPermitted IP Ranges: ")
		//fmt.Print(cert.PermittedIPRanges)
		//fmt.Print("\nEXcluded IP Ranges: ")
		//fmt.Print(cert.ExcludedIPRanges)
		//fmt.Print("\nPermitted Email Addresses: ")
		//fmt.Print(cert.PermittedEmailAddresses)
		//fmt.Print("\nExcluded Email Addresses: ")
		//fmt.Print(cert.ExcludedEmailAddresses)
		//fmt.Print("\nPermitted URI Domains: ")
		//fmt.Print(cert.PermittedURIDomains)
		//fmt.Print("\nExlucded URI Domains: ")
		//fmt.Print(cert.ExcludedURIDomains)
		//fmt.Print("\nOCSP Server: ")
		//fmt.Print(cert.OCSPServer)
		//fmt.Print("\nIssuing Certificate URL Server: ")
		//fmt.Print(cert.IssuingCertificateURL)
		//fmt.Print("\nDNS Names: ")
		//fmt.Println(cert.DNSNames)
	}
	return aRst, nil
}
