package lib

import "fmt"

// 聚合结果
// 开始、结束 时间使用任务 t2 的数据
func MergeResults(a *[]VulResults, rst *TastResultResponse, t2 *AlipayTaskDbSave) *TastResultResponse {
	var m1 = map[string]*VulsInfo{}
	var m2 = map[string][]Target{}
	for _, x := range *a {
		var bug1 = &VulsInfo{RiskType: "0"} // 0 普通漏洞  1 支付相关漏洞

		CopyObj(x, bug1) // 子项提取
		// 危害说明
		if "" != bug1.TemplateId {
			bug1.BugHazard = GetVulDesByTmpId(bug1.TemplateId)
		}
		if x1, ok := m1[bug1.TemplateId]; ok {
			bug1 = x1
		} else {
			m1[x.TemplateId] = bug1
			m2[bug1.TemplateId] = []Target{} // 初始化
			// 这里copy bug1 加到数组中
			rst.Bugs = append(rst.Bugs, *bug1)
		}
		var target = Target{VulUrl: x.ScanWeb, BugDetail: x.BugDetail, StartScan: fmt.Sprintf("%v", t2.CreatedAt), FinishTime: fmt.Sprintf("%v", t2.UpdatedAt)}
		m2[bug1.TemplateId] = append(m2[bug1.TemplateId], target)
	}
	for n, x := range rst.Bugs {
		rst.Bugs[n].Targets = m2[x.TemplateId]
	}
	return rst
}
