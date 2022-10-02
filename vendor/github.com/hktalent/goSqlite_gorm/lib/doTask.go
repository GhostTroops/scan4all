package lib

import (
	"fmt"
	"github.com/gin-gonic/gin"
	util "github.com/hktalent/go-utils"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"log"
	"net/http"
	"net/url"
	"time"
)

func Init() {
	for {
		select {
		case <-util.Ctx_global.Done(): // 退出
			return
			//case t := <-task: // 存储任务
			//var tDb = AlipayTaskDb{RunStatus: 1}
			//data, err := json.Marshal(t)
			//if nil == err {
			//	err = json.Unmarshal(data, &tDb)
			//	if nil == err {
			//		PutAny[AlipayTaskDb](tDb.TaskId, tDb)
			//		t1, err := GetAny[AlipayTaskDb](tDb.TaskId)
			//		if nil == err {
			//			log.Printf("任务保存成功: %+v", t1)
			//		} else {
			//			log.Printf("任务没有保存成功: %s %+v", t.TaskId, err)
			//		}
			//	}
			//}
		}
	}
}

// 保存 nuclei 结果
func SaveRsult4Ws(id string, m11 *map[string]interface{}, g1 *gin.Context, h *Hub, client *Client) {
	var resultEvent = output.ResultEvent{}
	//fmt.Printf("%+v", m11)
	if o, ok := (*m11)["event"]; ok {
		var BugSummary, BugLevel, BugDescription, Remediation string
		BugLevel = GetLevel(o.(map[string]interface{}))
		if m008, ok := o.(map[string]interface{}); ok {
			if info1, ok := m008["info"]; ok {
				if info, ok := info1.(map[string]interface{}); ok {
					if x1, ok := info["name"]; ok {
						BugSummary = fmt.Sprintf("%v", x1)
					}
					if x1, ok := info["description"]; ok {
						BugDescription = fmt.Sprintf("%v", x1)
					}
					if x1, ok := info["Remediation"]; ok {
						Remediation = fmt.Sprintf("%v", x1)
					}
				}
			}
			delete(m008, "info")
		}
		// cannot unmarshal array into Go struct field Info.info.author of type stringslice.StringSlice
		//var tags, reference, author string
		////  json: cannot unmarshal array into Go struct field Classification.info.classification.cve-id
		//if x02, ok := o.(map[string]interface{}); ok {
		//	if x04, ok := x02["info"]; ok {
		//		if x05, ok := x04.(map[string]interface{}); ok {
		//			tags = A2s(GetObj(&x05, "tags"))
		//			reference = A2s(GetObj(&x05, "reference"))
		//			author = A2s(GetObj(&x05, "author"))
		//		}
		//	}
		//}
		t11 := CopyObj(o, &resultEvent)
		if nil == t11 {
			// log.Printf("SaveRsult CopyObj 失败! %+v tags=%s reference = %s author=%s", m11, tags, reference, author)
			log.Printf("SaveRsult CopyObj 失败! %+v", m11)
		}
		// 保存结果
		if "" != id {
			//log.Printf("开始保存任务 %s 的结果", id)
			var rst = &VulResults{}
			rst.TaskId = id                                                     // 任务id
			rst.ScanWeb = resultEvent.Matched                                   // 漏洞url
			rst.BugSummary = BugSummary                                         // 漏洞摘要
			rst.BugDescription = BugDescription                                 // 漏洞描述
			rst.FixDetail = Remediation                                         // 修复方案
			rst.BugDetail = resultEvent.Request + "\n\n" + resultEvent.Response // 漏洞细节
			rst.BugLevel = BugLevel                                             // 漏洞等级
			rst.TemplateId = resultEvent.TemplateID                             // 模版（POC）id
			rst.RiskType = "0"                                                  // 普通漏洞
			rst.BugHazard = ""                                                  // 危害描述
			rst.FinishTime = fmt.Sprintf("%v", time.Now())

			rst.VulUrl = rst.ScanWeb
			var ats = AlipayTaskDbSave{}
			u01, err := url.Parse(rst.VulUrl)
			if nil != err {
				u01, _ = url.Parse(rst.ScanWeb)
			}
			x11 := GetOne[AlipayTaskDbSave](&ats, "task_id=? and scan_web like '"+u01.Scheme+"://"+u01.Host+"%'", id)
			if nil != x11 && "" != x11.ScanWeb {
				rst.ScanWeb = x11.ScanWeb
			}
			if 0 < Create[VulResults](rst) {
				if nil != g1 {
					g1.JSON(http.StatusOK, "ok")
				} else if h != nil {
					h.Ok(client)
				}
				//  UPDATE vuls.mz_info_mods c set c.poc_count = (SELECT COUNT(1) from (SELECT b.template_id from vuls.vul_results b,vuls.mz_info_mods a WHERE b.task_id = a.task_id and a.task_id='" + rst.TaskId + "'' GROUP by b.template_id) as xx);
				go DoSql("UPDATE vuls.mz_info_mods c set c.poc_count = (SELECT COUNT(1) from (SELECT b.template_id from vuls.vul_results b,vuls.mz_info_mods a WHERE b.task_id = a.task_id and a.task_id='" + rst.TaskId + "'' GROUP by b.template_id) as xx)")
				go func() {
					var oRt = VulResults{}
					x1 := GetOne[VulResults](&oRt, "task_id=? and template_id=?", rst.TaskId, rst.TemplateId)
					if nil == x1 || x1.TemplateId != rst.TemplateId {
						log.Printf("not save ok %s %s %s\n", rst.TaskId, rst.TemplateId, rst.ScanWeb)
					} else {
						log.Printf("save ok %s %s %s\n", rst.TaskId, rst.TemplateId, rst.ScanWeb)
					}
				}()
			} else {
				s009 := "结果保存失败: " + rst.TemplateId
				if nil != g1 {
					g1.JSON(http.StatusOK, s009)
				} else if h != nil {
					DoLog(s009, nil, client)
				}
				log.Println(s009)
			}
		} else {
			szE01 := "task id无效"
			err := errors.New(szE01)
			if nil != g1 {
				OutErr(g1, err, "400")
			} else if h != nil {
				DoLog(szE01, err, client)
			}
			log.Println(szE01)
		}
	} else {
		log.Printf("vuls info cannot found event")
	}
}
