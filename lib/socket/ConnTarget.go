package socket

import (
	"bufio"
	"fmt"
	"github.com/hktalent/scan4all/lib/Smuggling"
	"net"
	"strings"
	"time"
)

type CheckCbkFuc func(data byte) bool

type CheckTarget struct {
	Target        string         `json:"target"`
	Port          int            `json:"port"`
	ConnState     bool           `json:"connState"`
	ConnType      string         `json:"connType"`
	ReadTimeout   int            `json:"readTimeout"`
	CheckCbkLists []*CheckCbkFuc `json:"checkCbkLists"`
	Conn          *net.Conn      `json:"conn"`
}

// 准备要检测、链接带目标
func NewCheckTarget(target, SzType string, port, readWriteTimeout int) *CheckTarget {
	if "" == SzType {
		SzType = "tcp"
	}
	if 0 >= readWriteTimeout {
		readWriteTimeout = 20
	}
	return &CheckTarget{Target: target, Port: port, ConnType: SzType, ReadTimeout: readWriteTimeout, CheckCbkLists: []*CheckCbkFuc{}}
}

// 添加检测函数
// 如果检测函数返回true，就不关闭链接，继续发送后续带数据包
func (r *CheckTarget) AddCheck(fnCbk CheckCbkFuc, aN ...int) *CheckTarget {
	r.CheckCbkLists = append(r.CheckCbkLists, &fnCbk)
	return r
}

// send one payload and close
func (r *CheckTarget) SendOnePayload(str string) string {
	_, err := r.ConnTarget()
	if nil == err {
		defer r.Close()
		_, err := r.WriteWithFlush(Smuggling.TE_Payload[0])
		if err == nil {
			s1 := *r.ReadAll2Str()
			if "" != s1 {
				return s1
			}
		}
	}
	return ""
}

// 获取操作io
func (r *CheckTarget) WriteWithFlush(s string) (nn int, err error) {
	bw := r.GetBufWriter()
	nn, err = bw.Write([]byte(s))
	bw.Flush()
	return
}

// 获取操作io
func (r *CheckTarget) GetBufReader() *bufio.Reader {
	return bufio.NewReader(*r.Conn)
}

// 读取所有文本
func (r *CheckTarget) ReadAll2Str() *string {
	buf := r.GetBufReader()
	a := []string{}
	data := make([]byte, 1024)
	n, err := buf.Read(data)
	for nil == err {
		if 0 < n {
			a = append(a, string(data[0:n]))
		}
		n, err = buf.Read(data)
	}
	s1 := strings.Join(a, "")
	return &s1
}

func (r *CheckTarget) GetBufWriter() *bufio.Writer {
	return bufio.NewWriter(*r.Conn)
}

// 关闭连接
func (r *CheckTarget) Close() {
	if nil != r.Conn && r.ConnState {
		(*r.Conn).Close()
	}
}

// 连接目标
func (r *CheckTarget) ConnTarget() (*CheckTarget, error) {
	conn1, err := net.Dial(r.ConnType, fmt.Sprintf("%s:%d", r.Target, r.Port))
	if err != nil {
		return r, err
	}
	// 设置读取超时
	err = conn1.SetReadDeadline(time.Now().Add(time.Duration(r.ReadTimeout) * time.Second))
	if err != nil {
		defer (*r.Conn).Close()
		return r, err
	}
	//conn1.SetWriteDeadline(time.Now().Add(time.Duration(r.ReadTimeout) * time.Second))
	//if err != nil {
	//	return r, err
	//}
	r.ConnState = true
	r.Conn = &conn1
	return r, err
}
