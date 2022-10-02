package go_utils

import (
	"github.com/simonnilsson/ask"
)

func GetJson4Query(source interface{}, path string) interface{} {
	res := ask.For(source, path)
	if nil != res {
		return res.Value()
	}
	return nil
}
