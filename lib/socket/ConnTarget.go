package socket

import (
	"bufio"
	"fmt"
	"net"
	"time"
)

type CheckCbkFuc func(data byte) bool

type CheckTarget struct {
	Target        string         `json:"target"`        // 目标
	Port          int            `json:"port"`          // 端口
	ConnState     bool           `json:"connState"`     // 连接状态
	ConnType      string         `json:"connType"`      // 连接类型：tcp
	ReadTimeout   int            `json:"readTimeout"`   // 读数据超市
	CheckCbkLists []*CheckCbkFuc `json:"checkCbkLists"` // 回调接口
	Conn          *net.Conn      `json:"conn"`          // 连接对象
	MacReadSize   uint32         `json:"macReadSize"`   // 最大允许读取调数据，避免被反制内存攻击，default:200k
}

// 准备要检测、链接带目标
func NewCheckTarget(target, SzType string, port, readWriteTimeout int) *CheckTarget {
	if "" == SzType {
		SzType = "tcp"
	}
	if 0 >= readWriteTimeout {
		readWriteTimeout = 20
	}
	return &CheckTarget{MacReadSize: 200 * 1024 * 1024, Target: target, Port: port, ConnType: SzType, ReadTimeout: readWriteTimeout, CheckCbkLists: []*CheckCbkFuc{}}
}

// 添加检测函数
// 如果检测函数返回true，就不关闭链接，继续发送后续带数据包
func (r *CheckTarget) AddCheck(fnCbk CheckCbkFuc, aN ...int) *CheckTarget {
	r.CheckCbkLists = append(r.CheckCbkLists, &fnCbk)
	return r
}

// send one payload and close
func (r *CheckTarget) SendOnePayload(str string, nTimes int) string {
	_, err := r.ConnTarget()
	if nil == err {
		defer r.Close()
		for i := 0; i < nTimes; i++ {
			r.WriteWithFlush(str)
		}
		s1 := *r.ReadAll2Str()
		if "" != s1 {
			return s1
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

func (r *CheckTarget) ReadAll2Bytes() *[]byte {
	buf := r.GetBufReader()
	var a []byte
	data := make([]byte, 1024)
	var nCnt uint32 = 0
	n, err := buf.Read(data)
	for nil == err {
		if 0 < n {
			nCnt += uint32(n)
			a = append(a, data[0:n]...)
			// limit
			if nCnt >= r.MacReadSize {
				break
			}
		}
		n, err = buf.Read(data)
	}
	return &a
}

// 读取所有文本
func (r *CheckTarget) ReadAll2Str() *string {
	a := r.ReadAll2Bytes()
	s1 := string(*a)
	return &s1
}

func (r *CheckTarget) GetBufWriter() *bufio.Writer {
	return bufio.NewWriter(*r.Conn)
}

// 关闭连接
func (r *CheckTarget) Close() {
	if nil != r.Conn && r.ConnState {
		r.ConnState = false
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
	// 设置写超时
	//conn1.SetWriteDeadline(time.Now().Add(time.Duration(r.ReadTimeout) * time.Second))
	//if err != nil {
	//	return r, err
	//}
	r.ConnState = true
	r.Conn = &conn1
	return r, err
}
