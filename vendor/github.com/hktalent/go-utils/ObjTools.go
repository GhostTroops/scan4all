package go_utils

// convert any Object to T
func CvtObj2Any[T any](i interface{}) *T {
	var v1 = new(T)
	if data, err := json.Marshal(i); nil == err {
		if nil == json.Unmarshal(data, v1) {
			return v1
		}
	}
	return nil
}
