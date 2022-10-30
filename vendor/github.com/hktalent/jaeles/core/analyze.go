package core

import (
	"fmt"
	"github.com/hktalent/jaeles/utils"
)

func (r *Record) Analyze() {
	// print some log
	if r.Opt.Verbose && r.Request.Method != "" {
		if r.Response.StatusCode != 0 {
			fmt.Printf("[Sent] %v %v %v %v %v \n", r.Request.Method, r.Request.URL, r.Response.Status, r.Response.ResponseTime, len(r.Response.Beautify))
		}
		// middleware part
		if r.Request.MiddlewareOutput != "" {
			utils.DebugF(r.Request.MiddlewareOutput)
		}
	}

	if len(r.Sign.Origins) > 0 {
		r.Origins = r.Sign.Origins
	}

	r.Detector()
	if r.Opt.Mics.AlwaysTrue {
		r.IsVulnerable = true
		r.Output()
	}

	// set new values for next request here
	if len(r.Request.Conclusions) > 0 {
		r.Conclude()
	}

	// do passive analyze
	if r.Opt.EnablePassive || r.Sign.Passive || r.DoPassive {
		r.Passives()
	}
}
