package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

type (
	reportResult struct {
		Technique     string          `json:"technique"`
		HasError      bool            `json:"hasError"`
		ErrorMessages []string        `json:"errorMessages"`
		Vulnerable    bool            `json:"isVulnerable"`
		Requests      []reportRequest `json:"requests"`
	}

	reportRequest struct {
		URL      string `json:"-"`
		Reason   string `json:"reason"`
		Request  string `json:"request"`
		Response string `json:"response"`
	}

	reportSettings struct {
		ReportPath   string `json:"-"`
		IndentPrefix string `json:"-"`
		IndentSuffix string `json:"-"`
	}

	ReportWebsite struct {
		URL           string         `json:"url"`
		Vulnerable    bool           `json:"isVulnerable"`
		HasError      bool           `json:"hasError"`
		ErrorMessages []string       `json:"errorMessages"`
		Results       []reportResult `json:"results"`
	}

	Report struct {
		Settings      reportSettings `json:"-"`
		Name          string         `json:"name"`
		Version       string         `json:"version"`
		Vulnerable    bool           `json:"foundVulnerabilities"`
		HasError      bool           `json:"hasError"`
		ErrorMessages []string       `json:"errorMessages"`
		Date          string         `json:"date"`
		Duration      string         `json:"duration"`
		Command       string         `json:"command"`

		Config *ConfigStruct `json:"config,omitempty"`

		Websites []ReportWebsite `json:"websites"`
	}
)

func init() {

}

func GenerateReport(report Report, currentDate string) {
	reportPath := Config.GeneratePath + currentDate + "_WCVS_Report.json"

	var file *os.File
	defer file.Close()

	file, err := os.OpenFile(reportPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		msg := fmt.Sprintf("GenerateReport: os.OpenFile: %s\n", err.Error())
		PrintFatal(msg)
	}

	report.Settings.IndentPrefix = ""
	report.Settings.IndentSuffix = "    "
	if Config.EscapeJSON {
		j, err := json.MarshalIndent(report, report.Settings.IndentPrefix, report.Settings.IndentSuffix)
		if err != nil {
			msg := fmt.Sprintf("Generator: json.MarshalIndent: %s\n", err.Error())
			PrintFatal(msg)
		}

		file.WriteString(string(j))
	} else {
		bf := bytes.NewBuffer([]byte{})
		jsonEncoder := json.NewEncoder(bf)
		jsonEncoder.SetEscapeHTML(false)
		jsonEncoder.SetIndent(report.Settings.IndentPrefix, report.Settings.IndentSuffix)
		jsonEncoder.Encode(report)

		file.WriteString(bf.String())
	}
	msg := fmt.Sprintf("Exported report %s\n", reportPath)
	PrintVerbose(msg, NoColor, 1)

	report.Settings.ReportPath = reportPath
}
