package gss

import (
	"strconv"
	"strings"
)

func ObjectIDStrToInt(oid string) ([]int, error) {
	ret := []int{}
	tokens := strings.Split(oid, ".")
	for _, token := range tokens {
		i, err := strconv.Atoi(token)
		if err != nil {
			return nil, err
		}
		ret = append(ret, i)
	}
	return ret, nil
}
