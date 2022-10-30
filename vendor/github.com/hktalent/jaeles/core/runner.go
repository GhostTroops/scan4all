package core

import (
	"fmt"
	"github.com/hktalent/jaeles/libs"
	"github.com/hktalent/jaeles/sender"
	"github.com/hktalent/jaeles/utils"
	"strings"
)

// Runner runner struct
type Runner struct {
	Input       string
	SendingType string
	RunnerType  string
	Opt         libs.Options
	Sign        libs.Signature
	Origin      Record

	CRecords  []Record
	CMatched  bool
	InRoutine bool

	Target  map[string]string
	Records []Record
}

// Record all information about request
type Record struct {
	// main part
	Request  libs.Request
	Response libs.Response
	Sign     libs.Signature

	// for dns part
	Dns libs.Dns

	// passive check
	NoOutput            bool
	DoPassive           bool
	SelectPassive       string
	IsVulnerablePassive bool
	PassiveString       string
	PassiveMatch        string
	PassiveRules        map[string]libs.Rule

	OriginReq libs.Request
	OriginRes libs.Response
	Origins   []libs.Origin
	// for output
	Opt         libs.Options
	RawOutput   string
	ExtraOutput string
	// for detection
	PassCondition bool
	IsVulnerable  bool
	DetectString  string
	DetectResult  string
	ScanID        string
}

// InitRunner init task
func InitRunner(url string, sign libs.Signature, opt libs.Options) (Runner, error) {
	var runner Runner
	runner.Input = url
	runner.Opt = opt
	runner.Sign = sign
	runner.SendingType = "parallels"
	runner.PrepareTarget()

	if runner.Sign.Single || runner.Sign.Serial {
		runner.SendingType = "serial"
	}

	if runner.Sign.Local == true {
		runner.SendingType = "local"
	}

	// sending origin if we have it here
	if runner.Sign.Origin.Method != "" || runner.Sign.Origin.Res != "" {
		runner.PrePareOrigin()
	}

	if len(runner.Sign.CRequests) > 0 {
		runner.GenCRequests()
	}

	// generate requests
	runner.GetRequests()
	return runner, nil
}

func (r *Runner) PrepareTarget() {
	// clean up the '//' on hostname in case we use --ba option
	if r.Opt.Mics.BaseRoot || r.Sign.CleanSlash {
		r.Input = strings.TrimRight(r.Input, "/")
	}

	Target := make(map[string]string)
	// parse Input from JSON format
	if r.Opt.EnableFormatInput {
		Target = ParseInputFormat(r.Input)
	} else {
		Target = ParseTarget(r.Input)
	}

	// auto turn on baseRoot when we have prefix
	if r.Opt.Mics.BaseRoot || r.Sign.Replicate.Prefixes != "" {
		Target["BaseURL"] = Target["Raw"]
	}

	r.Sign.Target = Target
	r.Target = Target
}

// GetRequests get requests ready to send
func (r *Runner) GetRequests() {
	reqs := r.GenRequests()
	if len(reqs) > 0 {
		for _, req := range reqs {
			var rec Record
			// set somethings in record
			rec.Request = req
			rec.Request.Target = r.Target
			rec.Sign = r.Sign
			rec.Opt = r.Opt
			// assign origins here
			rec.OriginReq = r.Origin.Request
			rec.OriginRes = r.Origin.Response

			r.Records = append(r.Records, rec)
		}
	}
}

// GenRequests generate request for sending
func (r *Runner) GenRequests() []libs.Request {
	// quick param for calling resource
	r.Sign.Target = MoreVariables(r.Sign.Target, r.Sign, r.Opt)

	var realReqs []libs.Request
	globalVariables := ParseVariable(r.Sign)
	if len(globalVariables) > 0 {
		for _, globalVariable := range globalVariables {
			r.Sign.Target = r.Target
			for k, v := range globalVariable {
				r.Sign.Target[k] = v
			}
			// start to send stuff
			for _, req := range r.Sign.Requests {
				// receive request from "-r req.txt"
				if r.Sign.RawRequest != "" {
					req.Raw = r.Sign.RawRequest
				}
				// gen bunch of request to send
				realReqs = append(realReqs, ParseRequest(req, r.Sign, r.Opt)...)
			}
		}
	} else {
		r.Sign.Target = r.Target
		// start to send stuff
		for _, req := range r.Sign.Requests {
			// receive request from "-r req.txt"
			if r.Sign.RawRequest != "" {
				req.Raw = r.Sign.RawRequest
			}
			// gen bunch of request to send
			realReqs = append(realReqs, ParseRequest(req, r.Sign, r.Opt)...)
		}
	}
	return realReqs
}

// PrePareOrigin parsing origin request
func (r *Runner) PrePareOrigin() {
	var originRec libs.Record
	var origin libs.Origin
	// prepare initial signature and variables
	Target := make(map[string]string)
	Target = MoreVariables(r.Target, r.Sign, r.Opt)
	// base origin
	if r.Sign.Origin.Method != "" || r.Sign.Origin.Res != "" {
		origin, Target = r.SendOrigin(r.Sign.Origin)
		originRec.Request = origin.ORequest
		originRec.Response = origin.OResponse
	}

	// in case we have many origin
	if len(r.Sign.Origins) > 0 {
		var origins []libs.Origin
		for index, origin := range r.Sign.Origins {
			origin, Target = r.SendOrigin(origin.ORequest)
			if origin.Label == "" {
				origin.Label = fmt.Sprintf("%v", index)
			}
			origins = append(origins, origin)
		}
		r.Sign.Origins = origins
	}

	r.Target = Target
}

// SendOrigin sending origin request
func (r *Runner) SendOrigin(originReq libs.Request) (libs.Origin, map[string]string) {
	var origin libs.Origin
	var err error
	var originRes libs.Response
	originReq.EnableChecksum = true

	originSign := r.Sign
	if r.Opt.Scan.RawRequest != "" {
		RawRequest := utils.GetFileContent(r.Opt.Scan.RawRequest)
		originReq = ParseBurpRequest(RawRequest)
	}

	if originReq.Raw == "" {
		originSign.Target = r.Target
		originReq = ParseOrigin(originReq, originSign, r.Opt)
	}

	// parse response directly without sending
	if originReq.Res != "" {
		originRes = ParseBurpResponse("", originReq.Res)
	} else {
		originRes, err = sender.JustSend(r.Opt, originReq)
		if err == nil {
			if r.Opt.Verbose && (originReq.Method != "") {
				fmt.Printf("[Sent-Origin] %v %v %v %v %v\n", originReq.Method, originReq.URL, originRes.Status, originRes.ResponseTime, len(originRes.Beautify))
			}
		}
	}

	originRec := Record{Request: originReq, Response: originRes}
	// set some more variables
	originRec.Conclude()

	for k, v := range originSign.Target {
		if r.Target[k] == "" {
			r.Target[k] = v
		}
	}

	origin.ORequest = originReq
	origin.OResponse = originRes
	r.Origin = originRec

	if originRes.Checksum != "" {
		utils.DebugF("[Checksum Origin] %s - %s", originReq.URL, originRes.Checksum)
		r.Sign.Checksums = append(r.Sign.Checksums, originRes.Checksum)
	}
	return origin, r.Target
}

// GenCRequests generate condition requests
func (r *Runner) GenCRequests() {
	// quick param for calling resource
	r.Sign.Target = MoreVariables(r.Sign.Target, r.Sign, r.Opt)

	var realReqs []libs.Request
	globalVariables := ParseVariable(r.Sign)
	if len(globalVariables) > 0 {
		for _, globalVariable := range globalVariables {
			r.Sign.Target = r.Target
			for k, v := range globalVariable {
				r.Sign.Target[k] = v
			}
			// start to send stuff
			for _, req := range r.Sign.CRequests {
				// receive request from "-r req.txt"
				if r.Sign.RawRequest != "" {
					req.Raw = r.Sign.RawRequest
				}
				// gen bunch of request to send
				realReqs = append(realReqs, ParseRequest(req, r.Sign, r.Opt)...)
			}
		}
	} else {
		r.Sign.Target = r.Target
		// start to send stuff
		for _, req := range r.Sign.CRequests {
			// receive request from "-r req.txt"
			if r.Sign.RawRequest != "" {
				req.Raw = r.Sign.RawRequest
			}
			// gen bunch of request to send
			realReqs = append(realReqs, ParseRequest(req, r.Sign, r.Opt)...)
		}
	}

	if len(realReqs) > 0 {
		for _, req := range realReqs {
			var rec Record

			rec.NoOutput = true
			if r.Sign.COutput {
				rec.NoOutput = false
			}

			// set somethings in record
			rec.Request = req
			rec.Request.Target = r.Target
			rec.Sign = r.Sign
			rec.Opt = r.Opt
			// assign origins here
			rec.OriginReq = r.Origin.Request
			rec.OriginRes = r.Origin.Response

			r.CRecords = append(r.CRecords, rec)
		}
	}

}
