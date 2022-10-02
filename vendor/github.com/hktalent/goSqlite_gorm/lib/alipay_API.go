package lib

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"net/http"
	"strings"
)

// 签名失败 统一处理
func failSign(g *gin.Context) {
	g.JSON(http.StatusOK, &MSModle{Status: "300", Message: "签名失败"})
}

// 统一输出异常 400、500错误
func OutErr(g *gin.Context, err error, code string) {
	var ot = MSModle{}
	ot.Status = code
	if nil != err {
		ot.Message = fmt.Sprintf("%+v", err.Error())
	} else {
		ot.Message = "未知异常"
	}
	g.JSON(http.StatusOK, &ot)
}

// 更新验证签名密钥对
func UpdateKey(g *gin.Context) {
	var uk = UpdateKeyModel{}
	err := g.BindJSON(&uk)
	if nil != err {
		OutErr(g, err, "400")
		return
	}
	src := "key=" + uk.Key
	if CheckSign(src, uk.DataSign) {
		ok, err := SaveKey(uk.Key)
		if ok {
			g.JSON(200, MSModle{Message: "ok", Status: "200"})
		} else {
			g.JSON(200, MSModle{Message: fmt.Sprintf("%v", err), Status: "400"})
		}
	} else {
		failSign(g)
		return
	}
}

// 接收alipay任务
func Alipay_task(g *gin.Context) {
	var aTask = AlipayTask{}
	nLeft, _ := nim.GetTotal()
	var atr = &AlipayTaskResponse{FetchTime: 10, Capacity: nLeft}
	err := g.BindJSON(&aTask)
	if nil != err {
		OutErr(g, err, "400")
		return
	} else {
		src := "task_id=" + aTask.TaskId + "&" + "scan_web=" + aTask.ScanWeb
		// 数字签名检查
		if CheckSign(src, aTask.DataSign) {
			// 任务压入异步队列中
			aTask.ScanWeb = Base64Decode(aTask.ScanWeb)
			var err error
			var data []byte
			var t1 = AlipayTaskDbSave{}
			t2 := GetOne[AlipayTaskDbSave](&t1, "task_id=?", aTask.TaskId)
			if nil != t2 && aTask.TaskId == t2.TaskId {
				OutErr(g, errors.New("当前编号的任务已经存在"), "400")
				return
			}
			// 序列化，从新读取到 db 模型
			data, err = json.Marshal(aTask)
			// 没有找到才继续
			if nil == err {
				var tDb = AlipayTaskDb{RunStatus: 1}
				err = json.Unmarshal(data, &tDb)
				if nil == err {
					var x2 = AlipayTaskDbSave{}
					x3 := CopyObj[AlipayTaskDb, AlipayTaskDbSave](tDb, &x2)
					if 0 < Create[AlipayTaskDbSave](x3) {
						t2 := GetOne[AlipayTaskDbSave](&t1, "task_id=?", x3.TaskId)
						if nil != t2 && "" != t2.TaskId {
							atr.Status = "200"
							atr.Message = "ok"
							atr.FetchTime = 10 // 10 分钟, 单位 为： 分钟
							g.JSON(http.StatusOK, atr)
							return
						} else {
							OutErr(g, errors.New("验证、未成功保存任务"+tDb.TaskId), "400")
							return
						}
					} else {
						OutErr(g, errors.New("任务保存失败"), "400")
						return
					}
				}
			}
			OutErr(g, err, "400")
		} else { // 签名失败
			failSign(g)
			return
		}
	}
}

// 获取检测结果
func Alipay_task_query(g *gin.Context) {
	var tr TastResult
	//var rst = &TastResultResponse{}
	err := g.BindJSON(&tr)
	if nil != err {
		OutErr(g, err, "500")
		return
	} else {
		var src string = "task_id=" + tr.TaskId
		if "1" == tr.Op {
			src = "op=1&task_id=" + tr.TaskId
		}
		if CheckSign(src, tr.DataSign) {
			if "1" == tr.Op { // 异步推送停止任务
				var t1 = &AlipayTaskDbSave{}
				t1.RunStatus = 4
				if 0 < Update4Cust[AlipayTaskDbSave](t1, "task_id=?", tr.TaskId) {
					//g.JSON(http.StatusOK, "ok")
				} else {
					OutErr(g, errors.New("停止任务："+tr.TaskId+" 失败，无法保存任务"), "400")
				}
			}
			t1 := &AlipayTaskDbSave{}
			t2 := GetOne[AlipayTaskDbSave](t1, "task_id=? and (run_status=? or run_status=?)", tr.TaskId, 3, 4)
			// 任务已经结束、停止，才返回数据
			if nil != t2 && t2.TaskId == tr.TaskId {
				var trr = TastResultResponse{Bugs: []VulsInfo{}}
				var ats = VulResults{}
				var alist []VulResults
				trr.Status = "200"
				x1 := GetSubQueryLists[VulResults, VulResults](ats, "", alist, 100000, 0, "task_id=?", tr.TaskId)
				var trr1 *TastResultResponse
				trr1 = &trr
				if nil != x1 {
					trr1 = MergeResults(&x1, &trr, t2)
				}
				fmt.Printf("%+v", trr1)
				g.JSON(http.StatusOK, trr1)
				return
			} else {
				OutErr(g, errors.New("任务 "+tr.TaskId+" 未结束"), "400")
			}
		} else { // 签名失败
			failSign(g)
			return
		}
	}
}

// 获取来任务容量
// 容量计算算法，每个节点可以同时处理 15 个目标
// N(节点数) * 15 = 容量
func Alipay_query_ext(g *gin.Context) {
	var tr Limit
	//var rst = &LimitResponse{}
	err := g.BindJSON(&tr)
	if nil != err {
		OutErr(g, err, "400")
		return
	} else {
		if "true" == strings.ToLower(tr.QueryCapacityOnly) {
			src := "query_capacity_only=" + tr.QueryCapacityOnly
			// 获取容量前 先 验证签名
			if CheckSign(src, tr.DataSign) {
				// 获取容量
				nLeft, nT := nim.GetTotal()
				xR := &LimitResponse{Capcity: nLeft, TotalCapcity: nT}
				xR.Status = "200"
				// 返回结果
				g.JSON(http.StatusOK, xR)
			} else { // 签名失败
				failSign(g)
				return
			}
		} else {
			OutErr(g, errors.New("QueryCapacityOnly not is true"), "400")
		}
	}
}
