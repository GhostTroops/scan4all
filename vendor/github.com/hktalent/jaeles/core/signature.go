package core

import (
	"github.com/hktalent/jaeles/database"
	"github.com/hktalent/jaeles/libs"
	"github.com/hktalent/jaeles/utils"
	"github.com/thoas/go-funk"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// @NOTE: Signatures allow execute command on your machine
// So make sure you read the signature before you run it

// SelectSign select signature by multiple selector
func SelectSign(signName string) []string {
	var Signs []string
	// return default sign if doesn't set anything
	if signName == "**" {
		Signs = database.SelectSign("")
		return Signs
	}
	signs := SingleSign(strings.TrimSpace(signName))
	if len(signs) > 0 {
		Signs = append(Signs, signs...)
	}
	Signs = funk.UniqString(Signs)
	return Signs
}

// SingleSign select signature by single selector
func SingleSign(signName string) []string {
	signName = utils.NormalizePath(signName)

	var Signs []string
	// in case selector is file
	if strings.HasSuffix(signName, ".yaml") && !strings.Contains(signName, "*") {
		if utils.FileExists(signName) {
			Signs = append(Signs, signName)
		}
		return Signs
	}

	// in case selector is a folder
	if utils.FolderExists(signName) {
		signName = path.Join(path.Clean(signName), ".*")
	}

	// get more signature
	if strings.Contains(signName, "*") && strings.Contains(signName, "/") {
		asbPath, _ := filepath.Abs(signName)
		baseSelect := filepath.Base(signName)
		rawSigns := utils.GetFileNames(filepath.Dir(asbPath), "yaml")
		for _, signFile := range rawSigns {
			baseSign := filepath.Base(signFile)
			if len(baseSign) == 1 && baseSign == "*" {
				Signs = append(Signs, signFile)
				continue
			}
			r, err := regexp.Compile(baseSelect)
			if err != nil {
				if strings.Contains(signFile, baseSelect) {
					Signs = append(Signs, signFile)
				}
			}
			if r.MatchString(baseSign) {
				Signs = append(Signs, signFile)
			}
		}
	}
	return Signs
}

// AltResolveRequest resolve all request again but look for [[ ]] delimiter
func AltResolveRequest(req *libs.Request) {
	target := req.Target
	if len(req.Values) > 0 {
		for _, value := range req.Values {
			for k, v := range value {
				if strings.Contains(v, "{{.") && strings.Contains(v, "}}") {
					v = ResolveVariable(v, target)
				}
				// variable as a script
				if strings.Contains(v, "(") && strings.Contains(v, ")") {

					newValue := RunVariables(v)
					if len(newValue) > 0 {
						target[k] = newValue[0]
					}
				} else {
					target[k] = v
				}
			}
		}
	}
	// resolve all part again but with secondary template
	req.URL = AltResolveVariable(req.URL, target)
	req.Body = AltResolveVariable(req.Body, target)
	req.Headers = AltResolveHeader(req.Headers, target)
	req.Detections = AltResolveDetection(req.Detections, target)
	req.Generators = AltResolveDetection(req.Generators, target)
	req.Middlewares = AltResolveDetection(req.Middlewares, target)
}

// ResolveDetection resolve detection part in YAML signature file
func ResolveDetection(detections []string, target map[string]string) []string {
	var realDetections []string
	for _, detect := range detections {
		realDetections = append(realDetections, ResolveVariable(detect, target))
	}
	return realDetections
}

// AltResolveDetection resolve detection part in YAML signature file
func AltResolveDetection(detections []string, target map[string]string) []string {
	var realDetections []string
	for _, detect := range detections {
		realDetections = append(realDetections, AltResolveVariable(detect, target))
	}
	return realDetections
}

// ResolveHeader resolve headers part in YAML signature file
func ResolveHeader(headers []map[string]string, target map[string]string) []map[string]string {
	// realHeaders := headers
	var realHeaders []map[string]string

	for _, head := range headers {
		realHeader := make(map[string]string)
		for key, value := range head {
			realKey := ResolveVariable(key, target)
			realVal := ResolveVariable(value, target)
			realHeader[realKey] = realVal
		}
		realHeaders = append(realHeaders, realHeader)
	}

	return realHeaders
}

// AltResolveHeader resolve headers part in YAML signature file
func AltResolveHeader(headers []map[string]string, target map[string]string) []map[string]string {
	var realHeaders []map[string]string

	for _, head := range headers {
		realHeader := make(map[string]string)
		for key, value := range head {
			realKey := AltResolveVariable(key, target)
			realVal := AltResolveVariable(value, target)
			realHeader[realKey] = realVal
		}
		realHeaders = append(realHeaders, realHeader)
	}

	return realHeaders
}
