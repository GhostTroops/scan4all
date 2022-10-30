package lib

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// 客户端的操作封装
// 1、兼容存储http模式
// 2、同时支持websocket模式
type ClientOpt struct {
	g      *gin.Context
	client *Client
}

var re1 = regexp.MustCompile("[,;\\n]")

// 查询：
//  1、返回指定树木未执行的任务数据
//  2、更新 若干 指定任务 编号任务的执行状态，例如更新为执行结束
func (r *ClientOpt) QueryTask(q *QueryTaskForWs) {
	if nil == q {
		return
	}
	oRst := map[string]interface{}{"status": 400}
	szRst := ""
	n := q.Num
	leftNum := 30
	// 更新 "执行结束任务"的状态
	var sts = CvtData[SaveTaskStatus](q, r.client)
	if nil == sts {
		return
	}
	if 0 == sts.TaskNum {
		sts.TaskNum = 20
	}

	if 0 < n { // 需要获取任务
		var ats AlipayTaskDbSave
		var alist []AlipayTaskDbSave
		// 状态为4，表示需要停止的任务
		// 1000 = 节点数 * nuclei并发数 * 1.2
		x1 := GetSubQueryLists[AlipayTaskDbSave, AlipayTaskDbSave](ats, "", alist, 1000, 0, "run_status=? or run_status=?", 1, 4)
		defer func() {
			x1 = nil
		}()
		// 查询到任务
		if nil != x1 && 0 < len(x1) {
			var a1 []map[string]interface{}
			for _, j := range x1 {
				j.ScanWeb = strings.TrimSpace(j.ScanWeb)
				if 0 >= n {
					break
				}
				if "" == j.ScanWeb {
					continue
				}
				// 需要停止的任务
				if 4 == j.RunStatus {
					a1 = append(a1, map[string]interface{}{"scan_web": j.ScanWeb, "task_id": j.TaskId, "run_status": j.RunStatus})
				} else if 1 == j.RunStatus { // 更新任务状态为正在执行,待执行待才会更新为正在执行，已经是停止的不再更新
					n--
					j.RunStatus = 2
					j.CreatedAt = time.Now() // 便于计算任务耗时
					if 0 >= Update4Cust[AlipayTaskDbSave](&j, "id=? and run_status=1", j.ID) {
						//s001 := fmt.Sprintf("\n更新任务状态失败, %s ", j.TaskId)
						//log.Println(s001)
						//szRst += s001
					} else {
						a1 = append(a1, map[string]interface{}{"scan_web": j.ScanWeb, "task_id": j.TaskId, "run_status": 1})
					}
				}
			}
			oRst["task"] = a1
			oRst["status"] = 200
		} else {
			szRst += "\n没有查询到待执行、或需停止的任务"
		}
		leftNum = n
		x1 = nil
	} else {
		szRst += "\n任务容量不是正确的数字格式，或为0"
	}

	// 更新：1、节点容量；2、已经完成任务状态
	{
		go UpNodeTaskInfo(sts, sts.TaskNum, leftNum)
		if "" != sts.TaskIds {
			a := re1.Split(sts.TaskIds, -1)
			var a1 []string
			for _, x := range a {
				x = strings.ReplaceAll(strings.TrimSpace(x), "\"", "")
				if "" == x {
					continue
				}
				a1 = append(a1, x)
			}
			if 0 < len(a1) {
				szSql := "UPDATE alipay_task_db_saves SET run_status=3 WHERE task_id in ('" + strings.Join(a1, "','") + "')"
				n11 := DoSql(szSql)
				if 0 >= n11 { // 大于0 表示更新成功
					szSql := "select task_id from alipay_task_db_saves where run_status=3 and task_id in ('" + strings.Join(a1, "','") + "')"
					//if int64(len(a1)) > n11 {
					n22 := DoSql(szSql)
					if n22 != int64(len(a1)) {
						s101 := fmt.Sprintf("\n%s\n Failed to save task end status: update required %d == actual update %d,%d  %+v", szSql, int64(len(a1)), n11, n22, a1)
						szRst += s101
						log.Println(s101)
					}
				}
			}
		}
	}
	oRst["Message"] = szRst
	if nil != r.g {
		r.g.JSON(http.StatusOK, oRst)
	}
	if nil != r.client {
		r.client.send <- &ResponseData{Message: oRst, Status: http.StatusOK, EventId: q.EventId}
	}
}
