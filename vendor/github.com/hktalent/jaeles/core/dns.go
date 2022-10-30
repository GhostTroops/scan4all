package core

import (
	"fmt"
	"github.com/hktalent/jaeles/dns"
	"github.com/hktalent/jaeles/libs"
	"github.com/hktalent/jaeles/utils"
	"github.com/robertkrimen/otto"
	"regexp"
	"strings"
)

// InitDNSRunner init task
func InitDNSRunner(url string, sign libs.Signature, opt libs.Options) (Runner, error) {
	var runner Runner
	runner.Input = url
	runner.Opt = opt
	runner.Sign = sign
	runner.RunnerType = "dns"
	runner.PrepareTarget()

	// @NOTE: add some variables due to the escape issue
	runner.Target["RexDomain"] = regexp.QuoteMeta(runner.Target["Domain"])
	if strings.Contains(runner.Target["RexDomain"], `\.`) {
		runner.Target["RexDomain"] = strings.ReplaceAll(runner.Target["RexDomain"], `\.`, `\\.`)
	}

	return runner, nil
}

// Resolving get dns ready to resolve
func (r *Runner) Resolving() {
	if len(r.Sign.Dns) == 0 {
		return
	}
	for _, dnsRecord := range r.Sign.Dns {
		dnsRecord.Domain = ResolveVariable(dnsRecord.Domain, r.Target)
		dnsRecord.RecordType = ResolveVariable(dnsRecord.RecordType, r.Target)
		dnsRecord.Detections = ResolveDetection(dnsRecord.Detections, r.Target)
		dnsRecord.PostRun = ResolveDetection(dnsRecord.PostRun, r.Target)

		dns.QueryDNS(&dnsRecord, r.Opt)
		if len(dnsRecord.Results) == 0 {
			return
		}

		var rec Record
		// set somethings in record
		rec.Dns = dnsRecord
		rec.Sign = r.Sign
		rec.Opt = r.Opt
		r.Records = append(r.Records, rec)
	}

	r.DnsDetection()
}

// DnsDetection get requests ready to send
func (r *Runner) DnsDetection() {
	for _, rec := range r.Records {
		rec.DnsDetector()
	}
}

func (r *Record) DnsDetector() bool {
	record := *r
	var extra string
	vm := otto.New()

	// Only for dns detection
	vm.Set("DnsString", func(call otto.FunctionCall) otto.Value {
		args := call.ArgumentList
		recordName := "ANY"
		searchString := args[0].String()
		if len(args) > 1 {
			searchString = args[1].String()
			recordName = args[0].String()
		}
		content := GetDnsComponent(record, recordName)
		record.Response.Beautify = content
		result, _ := vm.ToValue(StringSearch(content, searchString))
		return result
	})

	vm.Set("DnsRegex", func(call otto.FunctionCall) otto.Value {
		args := call.ArgumentList
		recordName := "ANY"
		searchString := args[0].String()
		if len(args) > 1 {
			searchString = args[1].String()
			recordName = args[0].String()
		}
		content := GetDnsComponent(record, recordName)
		record.Response.Beautify = content

		matches, validate := RegexSearch(content, searchString)
		result, err := vm.ToValue(validate)
		if err != nil {
			utils.ErrorF("Error Regex: %v", searchString)
			result, _ = vm.ToValue(false)
		}
		if matches != "" {
			extra = matches
		}
		return result
	})

	// really run detection here
	for _, analyze := range record.Dns.Detections {
		// pass detection here
		result, _ := vm.Run(analyze)
		analyzeResult, err := result.Export()
		// in case vm panic
		if err != nil || analyzeResult == nil {
			r.DetectString = analyze
			r.IsVulnerable = false
			r.DetectResult = ""
			r.ExtraOutput = ""
			continue
		}
		r.DetectString = analyze
		r.IsVulnerable = analyzeResult.(bool)
		r.DetectResult = extra
		r.ExtraOutput = extra

		// add extra things for standard output
		r.Request.URL = r.Dns.Domain
		r.Request.Beautify = fmt.Sprintf("dig %s %s @%s", r.Dns.RecordType, r.Dns.Domain, r.Dns.Resolver)
		r.Response.Beautify = record.Response.Beautify

		utils.DebugF("[Detection] %v -- %v", analyze, r.IsVulnerable)
		// deal with vulnerable one here
		next := r.Output()
		if next == "stop" {
			return true
		}
	}

	return false
}

func GetDnsComponent(record Record, componentName string) string {
	var any string
	for _, dnsResult := range record.Dns.Results {
		if dnsResult.RecordType == strings.TrimSpace(componentName) {
			return dnsResult.Data
		}
		any += dnsResult.Data + "\n"
	}
	return any
}
