package core

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/hktalent/jaeles/libs"
	"github.com/hktalent/jaeles/utils"
	jsoniter "github.com/json-iterator/go"
	"github.com/logrusorgru/aurora/v3"
	"github.com/spf13/cast"
	"net/url"
	"os"
	"path"
	"strings"
)

func (r *Record) Output() string {
	if !r.IsVulnerable {
		return ""
	}
	utils.InforF("[Found] %v", color.MagentaString(r.DetectString))

	// do passive analyze if got called from detector
	if strings.Contains(strings.ToLower(r.DetectString), "dopassive") {
		r.Passives()
	}

	// @NOTE: Refactor
	//var outputName string
	outputName := ""
	if r.Opt.NoOutput == false && r.Sign.Noutput == false {
		r.StoreOutput()
		outputName = r.RawOutput

		// @NOTE: Disable viewing from UI from v0.14
		//if !r.Opt.NoDB {
		//	database.ImportRecord(*r)
		//}
	}

	vulnInfo := fmt.Sprintf("[%v][%v] %v", r.Sign.ID, r.Sign.Info.Risk, r.Request.URL)
	if r.Opt.Quiet {
		lTarget := make(map[string]string)
		lTarget["VulnURL"] = r.Request.URL
		lTarget["Payload"] = r.Request.Payload
		lTarget["payload"] = r.Request.Payload
		lTarget["Status"] = fmt.Sprintf("%v", r.Response.StatusCode)
		lTarget["Length"] = fmt.Sprintf("%v", r.Response.Length)
		lTarget["Words"] = fmt.Sprintf("%v", int64(len(strings.Split(r.Response.Beautify, " "))))
		lTarget["Time"] = fmt.Sprintf("%v", r.Response.ResponseTime)
		fmt.Printf("%v\n", ResolveVariable(r.Opt.QuietFormat, lTarget))
	} else {
		// use this libs because we still want to see color when use chunked mode
		au := aurora.NewAurora(true)
		colorSignID := fmt.Sprintf("%s", au.Cyan(r.Sign.ID))
		colorRisk := fmt.Sprintf("%s", au.BrightCyan(r.Sign.Info.Risk))
		risk := strings.ToLower(r.Sign.Info.Risk)
		switch risk {
		case "critical":
			colorRisk = fmt.Sprintf("%s", au.Red(r.Sign.Info.Risk))
		case "high":
			colorRisk = fmt.Sprintf("%s", au.BrightRed(r.Sign.Info.Risk))
		case "medium":
			colorRisk = fmt.Sprintf("%s", au.Yellow(r.Sign.Info.Risk))
		case "low":
			colorRisk = fmt.Sprintf("%s", au.BrightMagenta(r.Sign.Info.Risk))
		case "info":
			colorRisk = fmt.Sprintf("%s", au.Blue(r.Sign.Info.Risk))
		case "potential":
			colorRisk = fmt.Sprintf("%s", au.Magenta(r.Sign.Info.Risk))
		}
		info := fmt.Sprintf("[%s][%s][%s] %s %s", au.Green("Vulnerable"), colorSignID, colorRisk, au.Green(r.Request.URL), au.Green(outputName))
		fmt.Println(info)
	}
	if r.Opt.FoundCmd != "" {
		// add some more variables for notification
		r.Request.Target["vulnInfo"] = vulnInfo
		r.Request.Target["vulnOut"] = outputName
		r.Request.Target["notiText"] = vulnInfo
		r.Opt.FoundCmd = ResolveVariable(r.Opt.FoundCmd, r.Request.Target)
		Execution(r.Opt.FoundCmd)
	}

	if len(r.Request.PostRun) > 0 {
		r.Request.PostRun = ResolveDetection(r.Request.PostRun, r.Request.Target)
		for _, postrun := range r.Request.PostRun {
			Execution(postrun)
		}
	}

	//// do passive analyze if got called from detector
	//if strings.Contains(strings.ToLower(r.DetectString), "invokesign") {
	//	r.InvokeSign()
	// options.SignFolder/sign-name.yaml
	//}

	if r.Sign.Donce {
		return "stop"
	}
	return "continue"
}

// StoreOutput store vulnerable request to a file
func (r *Record) StoreOutput() {
	// disable out
	if r.NoOutput {
		return
	}
	// store output to a file
	if r.Request.URL == "" {
		r.Request.URL = r.Request.Target["URL"]
	}

	head := fmt.Sprintf("[%v][%v-%v] - %v\n", r.Sign.ID, r.Sign.Info.Confidence, r.Sign.Info.Risk, r.Request.URL)
	if r.Opt.VerboseSummary {
		// status-length-words-time
		moreInfo := fmt.Sprintf("%v-%v-%v-%v", r.Response.StatusCode, r.Response.Length, len(strings.Split(r.Response.Beautify, " ")), r.Response.ResponseTime)
		head = fmt.Sprintf("[%v][%v-%v][%v] - %v\n", r.Sign.ID, r.Sign.Info.Confidence, r.Sign.Info.Risk, moreInfo, r.Request.URL)
	}

	sInfo := fmt.Sprintf("[Sign-Info][%v-%v] - %v - %v\n", r.Sign.Info.Confidence, r.Sign.Info.Risk, r.Sign.RawPath, r.Sign.Info.Name)
	content := "[Vuln-Info]" + head + sInfo + fmt.Sprintf("[Detect-String] - %v\n\n", r.DetectString)
	if r.Request.MiddlewareOutput != "" {
		content += strings.Join(r.Request.Middlewares, "\n")
		content += fmt.Sprintf("\n<<%v>>\n", strings.Repeat("-", 50))
		content += r.Request.MiddlewareOutput
	}

	if r.ExtraOutput != "" {
		content += fmt.Sprintf("%v\n", strings.Repeat("-", 50))
		content += fmt.Sprintf("[Matches String]\n")
		content += strings.TrimSpace(r.ExtraOutput)
		content += fmt.Sprintf("\n")
	}

	content += fmt.Sprintf(">>>>%v\n", strings.Repeat("-", 50))
	if r.Request.MiddlewareOutput == "" {
		content += r.Request.Beautify
		content += fmt.Sprintf("\n%v<<<<\n", strings.Repeat("-", 50))
		content += r.Response.Beautify
	}

	// hash the content
	checksum := utils.GenHash(r.Response.Body)
	if r.Response.Body == "" {
		checksum = utils.GenHash(r.Response.Beautify)
	}

	parts := []string{r.Opt.Output}
	if r.Request.URL == "" {
		parts = append(parts, r.Request.Target["Domain"])
	} else {
		host := utils.StripName(r.Request.Host)
		u, err := url.Parse(r.Request.URL)
		if err == nil {
			host = u.Hostname()
		}
		if host == "" {
			host = URLEncode(r.Request.URL)
		}
		parts = append(parts, host)
	}
	parts = append(parts, fmt.Sprintf("%v-%s", r.Sign.ID, checksum))

	p := path.Join(parts...)
	if _, err := os.Stat(path.Dir(p)); os.IsNotExist(err) {
		err = os.MkdirAll(path.Dir(p), 0750)
		if err != nil {
			utils.ErrorF("Error Write content to: %v", p)
		}
	}
	// store output as JSON
	if r.Opt.JsonOutput {
		vulnData := libs.VulnData{
			SignID:          r.Sign.ID,
			SignName:        r.Sign.Info.Name,
			Risk:            r.Sign.Info.Risk,
			Confidence:      r.Sign.Info.Confidence,
			DetectionString: r.DetectString,
			DetectResult:    r.DetectResult,
			URL:             r.Request.URL,
			Req:             Base64Encode(r.Request.Beautify),
			Res:             Base64Encode(r.Response.Beautify),
		}
		if data, err := jsoniter.MarshalToString(vulnData); err == nil {
			content = data
		}
	}

	// detail normal output
	utils.WriteToFile(p, content)

	// summary file
	sum := fmt.Sprintf("%v - %v", strings.TrimSpace(head), p)
	if r.Opt.JsonOutput {
		vulnData := libs.VulnData{
			SignID:          r.Sign.ID,
			SignName:        r.Sign.Info.Name,
			Risk:            r.Sign.Info.Risk,
			Confidence:      r.Sign.Info.Confidence,
			DetectionString: r.DetectString,
			DetectResult:    r.DetectResult,
			URL:             r.Request.URL,
			StatusCode:      cast.ToString(r.Response.StatusCode),
			ContentLength:   cast.ToString(r.Response.Length),
			SignatureFile:   r.Sign.RawPath,
			OutputFile:      p,
		}
		if data, err := jsoniter.MarshalToString(vulnData); err == nil {
			sum = data
		}
	}
	utils.AppendToContent(r.Opt.SummaryOutput, sum)

	// file to parse single vulnerable
	vulnSum := fmt.Sprintf("[%v][%v] - %v", r.Sign.ID, r.Sign.Info.Risk, r.Request.Target["Raw"])
	utils.AppendToContent(r.Opt.SummaryVuln, vulnSum)
	r.RawOutput = p
}
