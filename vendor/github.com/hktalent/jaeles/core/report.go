package core

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/hktalent/jaeles/libs"
	"github.com/hktalent/jaeles/utils"
	"html/template"
	"path"
	"path/filepath"
	"strings"
)

type Vulnerability struct {
	SignID     string
	SignPath   string
	URL        string
	Risk       string
	Confidence string
	ReportPath string
	ReportFile string
	Status     string
	Length     string
	Words      string
	Time       string
}

type ReportData struct {
	Vulnerabilities []Vulnerability
}

// GenActiveReport generate report file
func GenActiveReport(options libs.Options) error {
	title := "Jaeles Active Report"
	if options.Report.Title != "" {
		title = options.Report.Title
	}
	// parse vulns from out/jaeles-summary.txt
	vulns := ParseVuln(options)
	if len(vulns) == 0 {
		return errors.New(fmt.Sprintf("no Vulnerability found from %v", options.Output))
	}
	data := struct {
		Vulnerabilities []Vulnerability
		CurrentDay      string
		Version         string
		Title           string
	}{
		Title:           title,
		Vulnerabilities: vulns,
		CurrentDay:      utils.GetCurrentDay(),
		Version:         libs.VERSION,
	}

	// read template file
	tmpl := utils.GetFileContent(options.Report.TemplateFile)
	if tmpl == "" {
		return errors.New("blank template file")
	}

	t := template.Must(template.New("").Parse(tmpl))
	buf := &bytes.Buffer{}
	err := t.Execute(buf, data)
	if err != nil {
		return err
	}
	result := buf.String()

	if !strings.Contains(options.Report.ReportName, "/") {
		options.Report.ReportName = path.Join(path.Dir(options.SummaryOutput), options.Report.ReportName)
	}
	utils.DebugF("Writing HTML report to: %v", options.Report.ReportName)
	_, err = utils.WriteToFile(options.Report.ReportName, result)

	// print result
	if err == nil {
		report, _ := filepath.Abs(options.Report.ReportName)
		utils.GoodF("Genereted Active HTML report: %v", report)
	}
	return err
}

// ParseVuln parse vulnerbility based on
func ParseVuln(options libs.Options) []Vulnerability {
	var vulns []Vulnerability
	utils.DebugF("Parsing summary file: %v", options.SummaryOutput)
	content := utils.ReadingLines(options.SummaryOutput)
	if len(content) == 0 {
		return vulns
	}

	for _, line := range content {
		data := strings.Split(line, " - ")
		if len(data) <= 0 {
			continue
		}
		if !strings.Contains(data[0], "][") {
			continue
		}
		if len(strings.Split(data[0], "][")) < 2 {
			continue
		}

		signID := strings.Split(data[0], "][")[0][1:]
		info := strings.Split(data[0], "][")[1][:len(strings.Split(data[0], "][")[1])-1]
		if options.VerboseSummary {
			info = strings.Split(data[0], "][")[1]
		}
		confidence := strings.Split(info, "-")[0]
		risk := strings.Split(info, "-")[1]

		raw := data[2]
		// host/sign-hash
		reportPath := path.Join(path.Base(path.Dir(raw)), filepath.Base(raw))

		vuln := Vulnerability{
			SignID:     signID,
			SignPath:   "SignPath",
			URL:        data[1],
			Risk:       risk,
			Confidence: confidence,
			ReportPath: reportPath,
			ReportFile: filepath.Base(raw),
		}

		// verbose info
		if options.VerboseSummary {
			if len(strings.Split(data[0], "][")) < 3 {
				utils.ErrorF("Summary doesn't have verbose format")
				return vulns
			}
			// status-length-words-time
			verbose := strings.Split(strings.Split(data[0], "][")[2], "-")
			if len(verbose) < 4 {
				utils.ErrorF("Summary doesn't have verbose format")
				return vulns
			}
			vuln.Status = verbose[0]
			vuln.Length = verbose[1]
			vuln.Words = verbose[2]
			vuln.Time = strings.Trim(verbose[3], "]")
		}
		vulns = append(vulns, vuln)
	}
	return vulns
}

///
/* Start passive part */
///

// GenPassiveReport generate report file
func GenPassiveReport(options libs.Options) error {
	title := "Jaeles Passive Report"
	if options.Report.Title != "" {
		title = options.Report.Title
	}
	// parse vulns from passive-out/jaeles-passive-summary.txt
	vulns := ParsePassiveVuln(options)
	if len(vulns) == 0 {
		return errors.New(fmt.Sprintf("no Passive found from %v", options.PassiveOutput))
	}
	data := struct {
		Vulnerabilities []Vulnerability
		CurrentDay      string
		Version         string
		Title           string
	}{
		Title:           title,
		Vulnerabilities: vulns,
		CurrentDay:      utils.GetCurrentDay(),
		Version:         libs.VERSION,
	}

	// read template file
	tmpl := utils.GetFileContent(options.Report.TemplateFile)
	if tmpl == "" {
		return errors.New("blank template file")
	}

	t := template.Must(template.New("").Parse(tmpl))
	buf := &bytes.Buffer{}
	err := t.Execute(buf, data)
	if err != nil {
		return err
	}
	result := buf.String()

	if !strings.Contains(options.Report.ReportName, "/") {
		options.Report.ReportName = path.Join(path.Dir(options.PassiveSummary), options.Report.ReportName)
	}
	utils.DebugF("Writing HTML report to: %v", options.Report.ReportName)
	_, err = utils.WriteToFile(options.Report.ReportName, result)

	// print result
	if err == nil {
		report, _ := filepath.Abs(options.Report.ReportName)
		utils.GoodF("Genereted Passive HTML report: %v", report)
	}
	return err
}

// ParsePassiveVuln parse vulnerbility based on
func ParsePassiveVuln(options libs.Options) []Vulnerability {
	var vulns []Vulnerability
	utils.DebugF("Parsing passive summary file: %v", options.PassiveSummary)
	content := utils.ReadingLines(options.PassiveSummary)
	if len(content) == 0 {
		return vulns
	}

	for _, line := range content {
		data := strings.Split(line, " - ")
		if len(data) <= 0 {
			continue
		}
		if !strings.Contains(data[0], "][") {
			continue
		}
		if len(strings.Split(data[0], "][")) < 3 {
			continue
		}

		signID := strings.Split(data[0], "][")[1]
		info := strings.TrimRight(strings.Split(data[0], "][")[2], "]")
		confidence := strings.Split(info, "-")[0]
		risk := strings.Split(info, "-")[1]

		raw := data[2]
		// host/sign-hash
		reportPath := path.Join(path.Base(path.Dir(raw)), filepath.Base(raw))

		vuln := Vulnerability{
			SignID:     signID,
			SignPath:   "SignPath",
			URL:        data[1],
			Risk:       risk,
			Confidence: confidence,
			ReportPath: reportPath,
			ReportFile: filepath.Base(raw),
		}
		vulns = append(vulns, vuln)
	}
	return vulns
}
