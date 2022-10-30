package core

import (
	"fmt"
	"github.com/hktalent/jaeles/libs"
	"github.com/hktalent/jaeles/sender"
	"github.com/hktalent/jaeles/utils"
	"github.com/thoas/go-funk"
)

var baseFiltering = []string{
	"hopetoget404" + RandomString(6),
	fmt.Sprintf("%s", RandomString(16)+"/"+RandomString(5)),
	fmt.Sprintf("%s.html", RandomString(16)),
	fmt.Sprintf("%%00%s", RandomString(16)),
	fmt.Sprintf("%s.json", RandomString(16)),
}

// BaseCalculateFiltering send couple of requests first to do filtering later
func BaseCalculateFiltering(job *libs.Job, options libs.Options) {
	utils.DebugF("Start Calculate Basic Filtering: %s", job.URL)
	// generated base calculate inputs first
	var baseFilteringURLs []string
	for _, filterPath := range baseFiltering {
		baseFilteringURLs = append(baseFilteringURLs, utils.JoinURL(job.URL, filterPath))
	}
	baseFilteringURLs = funk.UniqString(baseFilteringURLs)

	for _, filteringURL := range baseFilteringURLs {
		var req libs.Request
		req.Method = "GET"
		req.EnableChecksum = true
		req.URL = filteringURL

		res, err := sender.JustSend(options, req)
		// in case of timeout or anything, just ignore it
		if err != nil {
			return
		}

		// store the base result for local analyze if input is not a file
		if (req.URL == job.URL) || (req.URL == fmt.Sprintf("%s/", job.URL)) {
			job.Sign.Response = res
		}

		if res.Checksum != "" {
			utils.DebugF("[Checksum] %s - %s", req.URL, res.Checksum)
			job.Checksums = append(job.Checksums, res.Checksum)
		}
	}
	job.Checksums = funk.UniqString(job.Checksums)
}

func CalculateFiltering(job *libs.Job, options libs.Options) {
	var filteringPaths []string

	// ignore the base result if enabled from signature
	if job.Sign.OverrideFilerPaths {
		job.Sign.Checksums = []string{}
	} else {
		// mean doesn't have --fi in cli
		if len(job.Sign.Checksums) == 0 {
			filteringPaths = append(filteringPaths, baseFiltering...)
		}
	}
	if len(job.Sign.FilteringPaths) > 0 {
		filteringPaths = append(filteringPaths, job.Sign.FilteringPaths...)
	}

	if len(filteringPaths) == 0 {
		return
	}
	utils.DebugF("Start Calculate Custom Filtering: %s", job.URL)
	var FilteringURLs []string
	for _, filterPath := range filteringPaths {
		FilteringURLs = append(FilteringURLs, utils.JoinURL(job.URL, filterPath))
	}
	FilteringURLs = funk.UniqString(FilteringURLs)

	for _, filteringURL := range FilteringURLs {
		var req libs.Request
		req.Method = "GET"
		req.EnableChecksum = true
		req.URL = filteringURL

		res, err := sender.JustSend(options, req)
		// in case of timeout or anything
		if err != nil {
			return
		}

		// store the base result for local analyze if input is not a file
		if (req.URL == job.URL) || (req.URL == fmt.Sprintf("%s/", job.URL)) {
			job.Sign.Response = res
		}

		if res.Checksum != "" {
			utils.DebugF("[Checksum] %s - %s", req.URL, res.Checksum)
			job.Sign.Checksums = append(job.Sign.Checksums, res.Checksum)
		}
	}

	job.Sign.Checksums = funk.UniqString(job.Sign.Checksums)
}

func LocalFileToResponse(job *libs.Job) {
	if !utils.FileExists(job.URL) {
		return
	}
	utils.DebugF("Parsing %s to response", job.URL)

	// @TODO: add burp format here too
	content := utils.GetFileContent(job.URL)
	var res libs.Response

	res.Body = content
	res.Beautify = content

	job.Sign.Response = res
	job.Sign.Local = true
}
