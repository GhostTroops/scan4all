package runner

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	fileutil "github.com/projectdiscovery/utils/file"
)

func DoHealthCheck(options *Options, flagSet *goflags.FlagSet) string {
	// RW permissions on config file
	cfgFilePath, _ := flagSet.GetConfigFilePath()
	var test strings.Builder
	test.WriteString(fmt.Sprintf("Version: %s\n", version))
	test.WriteString(fmt.Sprintf("Operative System: %s\n", runtime.GOOS))
	test.WriteString(fmt.Sprintf("Architecture: %s\n", runtime.GOARCH))
	test.WriteString(fmt.Sprintf("Go Version: %s\n", runtime.Version()))
	test.WriteString(fmt.Sprintf("Compiler: %s\n", runtime.Compiler))

	var testResult string
	if privileges.IsPrivileged {
		testResult = "Ok"
	} else {
		testResult = "Ko"
	}
	test.WriteString(fmt.Sprintf("Privileged/NET_RAW: %s\n", testResult))

	ok, err := fileutil.IsReadable(cfgFilePath)
	if ok {
		testResult = "Ok"
	} else {
		testResult = "Ko"
	}
	if err != nil {
		testResult += fmt.Sprintf(" (%s)", err)
	}
	test.WriteString(fmt.Sprintf("Config file \"%s\" Read => %s\n", cfgFilePath, testResult))
	ok, err = fileutil.IsWriteable(cfgFilePath)
	if ok {
		testResult = "Ok"
	} else {
		testResult = "Ko"
	}
	if err != nil {
		testResult += fmt.Sprintf(" (%s)", err)
	}
	test.WriteString(fmt.Sprintf("Config file \"%s\" Write => %s\n", cfgFilePath, testResult))
	c4, err := net.Dial("tcp4", "scanme.sh:80")
	if err == nil && c4 != nil {
		c4.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	test.WriteString(fmt.Sprintf("TCP IPv4 connectivity to scanme.sh:80 => %s\n", testResult))
	c6, err := net.Dial("tcp6", "scanme.sh:80")
	if err == nil && c6 != nil {
		c6.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	test.WriteString(fmt.Sprintf("TCP IPv6 connectivity to scanme.sh:80 => %s\n", testResult))
	u4, err := net.Dial("udp4", "scanme.sh:53")
	if err == nil && c4 != nil {
		u4.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	test.WriteString(fmt.Sprintf("UDP IPv4 connectivity to scanme.sh:80 => %s\n", testResult))
	u6, err := net.Dial("udp6", "scanme.sh:80")
	if err == nil && c6 != nil {
		u6.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	test.WriteString(fmt.Sprintf("UDP IPv6 connectivity to scanme.sh:80 => %s\n", testResult))

	return test.String()
}
