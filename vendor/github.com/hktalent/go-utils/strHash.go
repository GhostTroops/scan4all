package go_utils

// 映射分布式服务器列表
type ArrHash struct {
	Data []interface{} // 这里可以是func，对象
}

// 获取数据
func (r *ArrHash) GetData(s string) interface{} {
	if 0 == len(r.Data) {
		return nil
	}
	return r.Data[int(GetStrHash(s))%len(r.Data)]
}
