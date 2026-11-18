package scan

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWhatsMyIP(t *testing.T) {
	// 依赖外部公网服务（api.ipify.org），默认跳过
	if "" == os.Getenv("SCAN4ALL_TEST_NET") {
		t.Skip("需要访问公网，设置 SCAN4ALL_TEST_NET=1 后再运行")
	}
	externalIp, err := WhatsMyIP()
	assert.Nil(t, err)
	assert.NotEmpty(t, externalIp)
}
