package lib

import (
	"github.com/gin-gonic/gin"
)

// 初始化 Api
func InitApiRouter(router *gin.Engine) {
	wsCbk := func(c *gin.Context) {
		Wshandler(c.Writer, c.Request)
	}
	wsP := "/rmtClientWss"
	// websocket
	router.GET(wsP, wsCbk)
	// 接收指纹数据匹配统计数据
	router.POST("/EventData", SendFg)

	//router.POST(wsP, wsCbk)

	// 商用/外部使用 Api 分组
	api := router.Group("/api/v1.0")
	// 更新 签名 key
	api.POST("/UpdateKey", UpdateKey)
	// 接收扫描任务
	api.POST("/alipay_task", Alipay_task)
	// 查询扫描任务结果
	api.POST("/alipay_task_query", Alipay_task_query) // curl -XPOST http://192.168.10.31:8080/api/v1.0/alipay_task_query -d '{"data_sign":"","task_id":"test0012928","op":"0"}'
	// 获取 平台任务扫描能力剩余容量
	api.POST("/alipay_query_ext", Alipay_query_ext)

	// 内部 Api 分组
	task := api.Group("/syncResult") //  http://127.0.0.1:8080/api/v1.0/syncResult/save/
	// nuclei 等，同一提交扫描结果，异步接收结果，不同的任务、不同的路由id
	router.POST("/:id/_doc", SaveRsult)
	// 取任务，同时通知哪些任务结束了、保存任务结束状态 http://127.0.0.1:8080/api/v1.0/syncResult/task/5
	task.Group("task").POST("/:num", QueryTask)
	// 获取当前运行状态
	api.GET("getCurStates", QueryProcess)
}
