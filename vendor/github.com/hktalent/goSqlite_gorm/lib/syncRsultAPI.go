package lib

import (
	"fmt"
	"github.com/gin-gonic/gin"
	util "github.com/hktalent/go-utils"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func GetObj(m *map[string]interface{}, key string) interface{} {
	if i, ok := (*m)[key]; ok {
		delete((*m), key)
		return i
	}
	return nil
}

// 获取风险级别
func GetLevel(m map[string]interface{}) string {
	if o, ok := m["info"]; ok {
		if m1, ok := o.(map[string]interface{}); ok {
			if o1, ok := m1["severity"]; ok {
				return fmt.Sprintf("%v", o1)
			}
		}
	}
	return ""
}

func A2s(o interface{}) string {
	if nil != o {
		if a, ok := o.([]string); ok {
			return strings.Join(a, ",")
		}
	}
	return ""
}

// 保存任务结果
func SaveRsult(g *gin.Context) {
	id := g.Param("id") // task id
	m11 := map[string]interface{}{}
	err := g.BindJSON(&m11)
	if nil != err {
		log.Println("SaveRsult bind error:", err)
	}
	SaveRsult4Ws(id, &m11, g, nil, nil)
}

// 分布式引擎节点查询任务
//
//	1、多节点获取任务时，任务不能重复
//	2、获取任务多同时处理已经完成任务的状态
//	3、同时更新任务容量数据
func QueryTask(g *gin.Context) {
	num := g.Param("num") // 希望返回的任务数量
	x1 := &ClientOpt{g: g}
	n, err := strconv.Atoi(num)
	if err != nil {
		log.Println(err)
		return
	}
	var sts = QueryTaskForWs{Num: n}
	errsts := g.BindJSON(&sts)
	if nil == errsts {
		x1.QueryTask(&sts)
	} else {
		g.JSON(404, err)
	}
	//num := g.Param("num") // 希望返回的任务数量
	//szRst := ""
	//oRst := map[string]interface{}{}
	//oRst["status"] = 400
	//leftNum := 30
	//// 更新 "执行结束任务"的状态
	//var sts = SaveTaskStatus{}
	//// 无参数时会自动修改头状态码
	//errsts := g.BindJSON(&sts)
	//
	//// 希望获取、并执行 num 个任务
	//if "" != num && nil == errsts && "" != sts.NodeId {
	//	n, err := strconv.Atoi(num) // 节点任务剩余容量，也是需要获取任务的个数
	//	if nil == err && 0 < n {
	//		var ats AlipayTaskDbSave
	//		var alist []AlipayTaskDbSave
	//		// 状态为4，表示需要停止的任务
	//		// 1000 = 节点数 * nuclei并发数 * 1.2
	//		x1 := GetSubQueryLists[AlipayTaskDbSave, AlipayTaskDbSave](ats, "", alist, 1000, 0, "run_status=? or run_status=?", 1, 4)
	//		defer func() {
	//			x1 = nil
	//		}()
	//		// 查询到任务
	//		if nil != x1 && 0 < len(x1) {
	//			var a1 []map[string]interface{}
	//			for _, j := range x1 {
	//				j.ScanWeb = strings.TrimSpace(j.ScanWeb)
	//				if 0 >= n {
	//					break
	//				}
	//				if "" == j.ScanWeb {
	//					continue
	//				}
	//				// 需要停止的任务
	//				if 4 == j.RunStatus {
	//					a1 = append(a1, map[string]interface{}{"scan_web": j.ScanWeb, "task_id": j.TaskId, "run_status": j.RunStatus})
	//				} else if 1 == j.RunStatus { // 更新任务状态为正在执行,待执行待才会更新为正在执行，已经是停止的不再更新
	//					n--
	//					j.RunStatus = 2
	//					j.CreatedAt = time.Now() // 便于计算任务耗时
	//					if 0 >= Update4Cust[AlipayTaskDbSave](&j, "id=? and run_status=1", j.ID) {
	//						//s001 := fmt.Sprintf("\n更新任务状态失败, %s ", j.TaskId)
	//						//log.Println(s001)
	//						//szRst += s001
	//					} else {
	//						a1 = append(a1, map[string]interface{}{"scan_web": j.ScanWeb, "task_id": j.TaskId, "run_status": 1})
	//					}
	//				}
	//			}
	//			oRst["task"] = a1
	//			oRst["status"] = 200
	//		} else {
	//			szRst += "\n没有查询到待执行、或需停止的任务"
	//		}
	//		leftNum = n
	//		x1 = nil
	//	} else {
	//		szRst += "\n任务容量不是正确的数字格式，或为0"
	//	}
	//}
	//
	//if nil == errsts {
	//	if 0 == sts.TaskNum {
	//		sts.TaskNum = 20
	//	}
	//	go UpNodeTaskInfo(&sts, sts.TaskNum, leftNum)
	//	if "" != sts.TaskIds {
	//		re1 := regexp.MustCompile("[,;\\n]")
	//		a := re1.Split(sts.TaskIds, -1)
	//		var a1 []string
	//		for _, x := range a {
	//			x = strings.ReplaceAll(strings.TrimSpace(x), "\"", "")
	//			if "" == x {
	//				continue
	//			}
	//			a1 = append(a1, x)
	//		}
	//		if 0 < len(a1) {
	//			szSql := "UPDATE alipay_task_db_saves SET run_status=3 WHERE task_id in ('" + strings.Join(a1, "','") + "')"
	//			n11 := DoSql(szSql)
	//			if 0 >= n11 { // 大于0 表示更新成功
	//				//if int64(len(a1)) > n11 {
	//				n22 := DoSql(szSql)
	//				s101 := fmt.Sprintf("\n%s\n Failed to save task end status: update required %d == actual update %d,%d  %+v", szSql, int64(len(a1)), n11, n22, a1)
	//				szRst += s101
	//				log.Println(s101)
	//			}
	//		}
	//	}
	//} else {
	//	szRst += fmt.Sprintf("%v", errsts)
	//}
	//oRst["Message"] = szRst
	//g.JSON(http.StatusOK, oRst)
}

// 任务容量信息
var nim = &NodeInfoManager{}

// 更新节点 任务容量信息
func UpNodeTaskInfo(sts *SaveTaskStatus, taskNum, leftNum int) {
	if nil != sts && "" != sts.NodeId {
		nim.Put(sts.NodeId, taskNum, leftNum)
	}
}

type ProcessMod struct {
	Maxtm      float64 `json:"maxtm"`
	Mintm      float64 `json:"mintm"`
	OkTask     int64   `json:"okTask"`
	PlugNum    int64   `json:"plugNum"`
	RunStatus3 int64   `json:"run_status3"`
	RunStatus2 int64   `json:"run_status2"`
}

func QueryProcess(g *gin.Context) {
	szSql := `SELECT
(SELECT max(updated_at) from vuls.alipay_task_db_saves atds WHERE run_status=3) as maxtm,
(SELECT min(created_at) from vuls.alipay_task_db_saves atds WHERE run_status=3) as mintm,
((SELECT max(UNIX_TIMESTAMP(updated_at)) from vuls.alipay_task_db_saves atds WHERE run_status=3) -
(SELECT min(UNIX_TIMESTAMP(created_at)) from vuls.alipay_task_db_saves atds WHERE run_status=3) )/60 as tm,
(SELECT count(1) FROM vuls.alipay_task_db_saves WHERE run_status =3) as okTask,
(SELECT count(1) from (SELECT template_id,count(1) cnt from vuls.vul_results  group by template_id) as xx) as plugNum,
(SELECT  count(1) FROM vuls.alipay_task_db_saves WHERE run_status =3) as run_status3,
(SELECT  count(1) FROM vuls.alipay_task_db_saves WHERE run_status =2) as run_status2;`
	var xR = ProcessMod{}
	util.DoSelectSql(&xR, szSql)
	g.JSON(http.StatusOK, xR)
}

// 接收、处理事件数据
func SendFg(g *gin.Context) {
	var msg = &EventData{}
	if err := g.BindJSON(msg); nil != err {
		log.Println(err)
	} else {
		hub.ReceveEventData <- *msg
		g.JSON(200, "ok")
	}
}
