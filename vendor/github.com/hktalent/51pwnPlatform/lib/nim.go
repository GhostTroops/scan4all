package lib

import (
	"sync"
	"time"
)

// 节点信息
// 考虑将当前并发的 20个目标的id、target 存放这里
//
//	1、确保各节点任务id不重复
//	2、节点任务完成时，在这里移除
type NodeInfo struct {
	TaskNum  int    `json:"task_num"`  // 当前节点任务并发数，总任务容量计算
	LeftNum  int    `json:"left_num"`  // 还可以做的任务数
	NodeId   string `json:"node_id"`   // 节点唯一id，可以用Mac地址
	DateTime int64  `json:"date_time"` // 最后更新时间
}

// 容量计算用，节点信息管理
type NodeInfoManager struct {
	sync.Map
}

func (r *NodeInfoManager) Put(key string, taskNum, leftNum int) {
	if ni, ok := r.Load(key); ok {
		var ni1 *NodeInfo
		ni1 = ni.(*NodeInfo)
		ni1.TaskNum = taskNum
		ni1.LeftNum = leftNum
		ni1.DateTime = time.Now().UnixMilli()
		r.Delete(key)
		r.Store(key, ni1)
	} else {
		r.Store(key, &NodeInfo{NodeId: key, TaskNum: taskNum, LeftNum: leftNum, DateTime: time.Now().UnixMilli()})
	}
	r.RemoveOld()
}

func (r *NodeInfoManager) RemoveOld() {
	r.Range(func(key, value any) bool {
		if v, ok := value.(*NodeInfo); ok {
			// 超过30秒未刷新的删除
			if 30 < (time.Now().UnixMilli()-v.DateTime)/1000 {
				r.Store(key, nil)
				r.Delete(key)
			}
		}
		return true
	})
	return
}

// 获取任务容量信息
//
//	nLeft 总的剩余容量
//	nTask 总任务量
func (r *NodeInfoManager) GetTotal() (nLeft, nTask int) {
	nLeft, nTask = 0, 0
	r.Range(func(key, value any) bool {
		if v, ok := value.(*NodeInfo); ok {
			nLeft += v.LeftNum
			nTask += v.TaskNum
		}
		return true
	})
	return
}
