package pkg

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"os"
	"strings"
)

var NoColor bool
var Output = ""

func POClog(log string) {
	builder := &strings.Builder{}
	builder.WriteString(aurora.BrightRed("[POC] ").String())
	if !NoColor {
		builder.WriteString(aurora.BrightRed(log).String())
	} else {
		builder.WriteString(log)
	}
	fmt.Print(builder.String())
	if Output != "" {
		writeoutput(builder.String())
	}

}

func writeoutput(log string) {
	f, err := os.OpenFile(Output, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		gologger.Fatal().Msgf("Could not create output fiale '%s': %s\n", Output, err)
	}
	defer f.Close() //nolint
	f.WriteString(log)
}
