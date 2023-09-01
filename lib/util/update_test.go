package util

import (
	"testing"
)

// 更新到最新版本
func TestUpdateScan4allVersionToLatest(t *testing.T) {
	err := UpdateScan4allVersionToLatest(true)
	if err != nil {
		t.Error("fail TestupdateNucleiVersionToLatest")
	}
}
