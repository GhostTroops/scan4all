package engine

import (
	"bytes"
	"context"
	"fmt"
	"github.com/hktalent/51pwnPlatform/lib"
	"github.com/hktalent/51pwnPlatform/pkg/models"
	"github.com/hktalent/ProScan4all/lib/util"
	"github.com/hktalent/ProScan4all/pocs_go"
	"github.com/hktalent/jaeles/cmd"
	jsoniter "github.com/json-iterator/go"
	"github.com/panjf2000/ants/v2"
	"github.com/ulule/deepcopier"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// 引擎对象，全局单实例
type Engine struct {
	Context      *context.Context       // 上下文
	Wg           *sync.WaitGroup        // Wg
	Pool         int                    // 线程池
	PoolFunc     *ants.PoolWithFunc     // 线程调用
	EventData    chan *models.EventData // 数据队列
	NodeId       string                 `json:"node_id"`    // 分布式引擎节点的id，除非系统更换，docker重制，否则始终一致
	LimitTask    int                    `json:"limit_task"` // 当前节点任务并发数的限制
	SyTask       int                    `json:"sy_task"`    // 剩余task
	DtServer     string                 `json:"dt_server"`  // 获取任务、提交任务状态的server
	caseScanFunc sync.Map
}

var GEngine *Engine

// 获取分布式任务
// /api/v1.0/syncResult/task/

// 创建引擎
//  默认每个 goroutine 占用 8KB 内存
//  一台 8GB 内存的机器满打满算也只能创建 8GB/8KB = 1000000 个 goroutine
//  更何况系统还需要保留一部分内存运行日常管理任务，go 运行时需要内存运行 gc、处理 goroutine 切换等
func NewEngine(c *context.Context, pool int) *Engine {
	if nil != util.G_Engine {
		return util.G_Engine.(*Engine)
	}

	x1 := &Engine{
		Context:   c,
		Wg:        &sync.WaitGroup{},
		Pool:      pool,
		DtServer:  util.GetVal("DtServer"),
		EventData: make(chan *models.EventData, pool),
		LimitTask: util.GetValAsInt("LimitTask", 4),
	}
	x1.SyTask = x1.LimitTask // 初始化剩余任务等于最大任务数
	x1.initNodeId()
	p, err := ants.NewPoolWithFunc(pool, func(i interface{}) {
		defer x1.Wg.Done()
		x1.DoEvent(i.(*models.EventData))
	}, ants.WithPreAlloc(true))
	if nil != err {
		log.Println("ants.NewPoolWithFunc is error: ", err)
	}
	x1.PoolFunc = p
	util.G_Engine = x1
	GEngine = x1
	util.EngineFuncFactory = x1.EngineFuncFactory
	util.SendEvent = x1.SendEvent
	log.Println("Engine init ok")
	return x1
}

func (e *Engine) initNodeId() {
	dirname, err := os.Getwd()
	szP := dirname + "/.DistributedId"
	if nil == err {
		if util.FileExists(szP) {
			data, err := ioutil.ReadFile(szP)
			if nil == err {
				e.NodeId = strings.TrimSpace(string(data))
			}
		}
	}
	if "" == e.NodeId {
		e.NodeId = util.GenUuid()
		ioutil.WriteFile(szP, []byte(e.NodeId), os.ModePerm)
	}
}

// "https://dt.51pwn.com/api/v1.0/syncResult/task/%d"
// curl -v -XPOST -d '{"Num":22,"task_ids":"","node_id":"xx","task_num":443}'  https://127.0.0.1:8081/api/v1.0/syncResult/task/33
// 结果反馈 /api/v1.0/syncResult/task/%d
// 获取、确认分布式任务，Distributed Tasks
func (e *Engine) GetTask(okTaskIds string) {
	if resp, err := util.DoPost(fmt.Sprintf(e.DtServer, e.LimitTask), map[string]string{
		"Content-Type": "application/json",
	}, strings.NewReader(`{"Num":`+strconv.Itoa(e.SyTask)+`,"task_ids":"`+okTaskIds+`","node_id":"`+e.NodeId+`","task_num":`+strconv.Itoa(e.LimitTask)+`}`)); nil == err && nil != resp {
		defer resp.Body.Close()
		var n1 = models.EventData{}
		if data, err := ioutil.ReadAll(resp.Body); nil == err {
			if err := json.Unmarshal(data, &n1); nil == err {
				e.SendEvent(&n1, n1.EventType)
			}
		}
	}
}

// 获取公共ip
func (r *Engine) GetPublicIP() ([]string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var as []string

	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		// have mac
		if a != "" {
			addrs, err := ifa.Addrs()
			// get Ip error
			if nil != err {
				continue
			}
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					if v.IP.IsPrivate() {
						continue
					}
					as = append(as, v.IP.String())
				case *net.IPAddr:
					if v.IP.IsPrivate() {
						continue
					}
					as = append(as, v.IP.String())
				}
			}
		}
	}
	return as, nil
}
func (e *Engine) generateTaskId(s string) string {
	return util.GetSha1(s)
}

// 发送任务
//  只发送非私有网络的任务
func (e *Engine) SendTask(s string) {
	szUrl := fmt.Sprintf(e.DtServer, e.LimitTask)
	if oU, err := url.Parse(szUrl); nil == err {
		szUrl = strings.Join([]string{oU.Scheme, "://", oU.Host, "/api/v1.0/alipay_task"}, "")
		szSendData := ""
		sW := util.Base64Encode(s)
		szTaskId := e.generateTaskId(s)
		szSendData = "task_id=" + szTaskId + "&" + "scan_web=" + sW
		base64Str := util.GetSig(szSendData, prvKey)
		m1 := map[string]string{"task_id": szTaskId, "op": "0", "data_sign": base64Str}
		data, _ := json.Marshal(&m1)

		if resp, err := util.DoPost(fmt.Sprintf(e.DtServer, e.LimitTask), map[string]string{
			"Content-Type": "application/json",
		}, bytes.NewReader(data)); nil == err && nil != resp {
			defer resp.Body.Close()
			var n1 = models.EventData{}
			if data, err := ioutil.ReadAll(resp.Body); nil == err {
				if err := json.Unmarshal(data, &n1); nil == err {
					e.SendEvent(&n1, n1.EventType)
				}
			}
		}
	}
}

func (e *Engine) EngineFuncFactory(nT int64, fnCbk interface{}) {
	e.RegCaseScanFunc(nT, fnCbk)
}

func (e *Engine) RegCaseScanFunc(nType int64, fnCbk interface{}) {
	e.caseScanFunc.Store(nType, fnCbk)
}

func (r *Engine) GetCaseScanFunc() *sync.Map {
	return &r.caseScanFunc
}

// 释放资源
func (e *Engine) Close() {
	defer ants.Release()
	e.PoolFunc.Release()
	e.Wg.Wait()
	cmd.CleanOutput()
}

// case 扫描使用的函数
func (e *Engine) DoCase(ed *models.EventData) util.EngineFuncType {
	if i, ok := e.caseScanFunc.Load(ed.EventType); ok {
		return i.(util.EngineFuncType)
	}
	return nil
}

// 关联发送若干个事件
func (e *Engine) SendEvent(evt *models.EventData, argsTypes ...int64) {
	for _, i := range argsTypes {
		var n1 = models.EventData{}
		deepcopier.Copy(evt).To(n1)
		n1.EventType = i
		e.EventData <- &n1
	}
}

// 执行事件代码 内部用
//  每个事件自己做防重处理
//  每个事件异步执行
//  每种事件类型可以独立控制并发数
func (e *Engine) DoEvent(ed *models.EventData) {
	if nil != ed && nil != ed.EventData && 0 < len(ed.EventData) {
		fnCall := e.DoCase(ed)
		if nil != fnCall {
			fnCall(ed, ed.EventData...)
		} else {
			log.Printf("can not find fnCall case func %v\n", ed)
		}
	}
}

func (x1 *Engine) Running() {
	// 异步启动一个线程处理检测，避免
	go func() {
		defer func() {
			x1.Close()
		}()
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		//nMax := 120 // 等xxx秒都没有消息进入就退出
		//nCnt := 0
		// 每10秒获取一次任务
		c1Task := time.NewTicker(5 * time.Second)
		c2Task := time.NewTicker(15 * time.Second)
		for {
			select {
			case <-util.Ctx_global.Done():
				close(util.PocCheck_pipe)
				return
			case <-c:
				util.DoCbk("exit")
				os.Exit(1)
			case l1, ok := <-util.OutLogV:
				if ok {
					util.WriteLog2File(l1)
				}
			case x2 := <-x1.EventData: // 各种扫描的控制
				if nil != x2 && nil != x2.EventData {
					x1.Wg.Add(1)
					x1.PoolFunc.Invoke(x2)
				}
			case x1, ok := <-util.PocCheck_pipe:
				if util.GetValAsBool("NoPOC") || nil == x1 || !ok {
					//close(util.PocCheck_pipe) // 这行会在 NoPOC该标志开启时，其他进程无法传递过来而出错
					log.Println("go_poc_checkout is over")
					continue
				}
				//nCnt = 0
				if !util.TestRepeat(x1, *x1.Wappalyzertechnologies, x1.URL) {
					log.Printf("<-util.PocCheck_pipe: %+v  %s", *x1.Wappalyzertechnologies, x1.URL)
					func(x99 *util.PocCheck) {
						util.DoSyncFunc(func() {
							pocs_go.POCcheck(*x99.Wappalyzertechnologies, x99.URL, x99.FinalURL, x99.Checklog4j)
						})
					}(x1)
				}
			case <-c1Task.C:
				x1.GetTask("")
			case <-c2Task.C:
				util.DoDelayClear(x1.Wg) // panic: sync: WaitGroup misuse: Add called concurrently with Wait
			default:
				//util.DoSleep()
			}
		}
	}()
}

// 引擎总入口
func init() {
	//log.Println("engineImp.go run")
	lib.GConfigServer.OnClient = true
	lib.MyHub.FnClose()
	util.RegInitFunc4Hd(func() {
		// 下面的变量 不能移动到DoSyncFunc，否则全局变量将影响后续的init，导致无效的内存
		NewEngine(&util.Ctx_global, util.GetValAsInt("ScanPoolSize", 5000))

		util.DoSyncFunc(func() {
			util.G_Engine.(*Engine).Running()
		})
	})
}

// 发送方 的签名key
var prvKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,0B3A74436D1F0AAE

hzXeizI3DX5udIFmtfBpIEbQYz4ConOmdD/Vel2ppj6EG8PLI3oirlH7eRKxsCtU
khRVyYhUhb9II1jKF0tu7glnZabHnTGFAeo5nEXjTl/dp5Of6eJIaNcWlc7nXTft
koodNonRFZtGe7cHI5+WM4AvjWEXztuyPKCa0Zepz7k77IdxxQ+gzIonbni0OGeh
ze2kkBZMgCnS2LNqhk5zAhb0ATCTMLfd1FbsJXieXQAyCZQBER6J8hXvvZP2oZyq
izou+5BsT9/W/4crq0glYSc2SMSWUFj5sSSPgVj7dV8KiRueD1ybm13B0N5XKEoY
YK+IfdVBu6NspMfW8b+mp4JoAChA360d12Zyrg4J9gtOvoR4eOhtm4c0D0GPsubS
XjK8Jvp41QtLRz9trNshrXI8/3z5bc26zHBLbQ6lRJSA9Q5Guc70/8FHxPOik+SZ
57gMsG0OuxvUfoIif5dwwtYh5dWYktE+Ii/FnFH/X3wROiq+D4ZWI0dKNED7fFry
RYmLJK+Bn7BjbzC+ZWwmKgMpmZyKF1/AB7031rB77z5Zq4Ksk+F5UEGLA4287CRT
6vYY7eKpkRnZ2QHI5fdQ+fZ/A40n3NO1letf2MXB6Fxcz1P2DMYGJVVHfNSurj32
F2fUckcHe9Kvy5FCXwui7aXZUkhbREAnAiKFHeRwlyjYUwxeo9QZUHt06hUKaY4c
HJOLBzpjErtRfYLtGLADzaKAPe+fV+FqBWquoOG3/3aoz9oiiyxIj2a9D9ORLsy+
e3QgdgiAluQ2QMqdNeYO7POWXjasaqZ8XVanSCHn3Tw5GdEq6naWz4cGxaJiXHV1
PTiH2g/KEgu+L6b2xnwvEmpOKD33DEkB5xlnqUUFzAksbpL8l/sk9LPRjbjHl2Nu
yL9myaJgpbPhw12Ika97VJp6ooH7Qy2WRGJ67FXGBkXXpTcItQzqqs6ZIFdwadq6
Z1jNv+Wiq/o8IuVZys0a/LJlYYKrnHvKVl6LQrmcd+SWUgwbbKUBytsMDPB6OwHB
Qrf3flcVIYvgqS+R1745JeFK/kxI1vtYlyNlveiAi9yRtDVnw+0DWrY03kWNsGfg
9swsfO+/nHUxf81hC2g/Carrkdz7BLrsMKZnHlNVVFTNsHeELpmlGIO4VxOJzjel
nuz4sITlXjBPsZernQuIbJ7GYqDv8Zb/dsW47BqIcl0PQ5FLOjJYBcIjpOnU1tLn
e6pShBS4KWK/YegJdo+SxDvqLl66fdn58s1TlaZfgQic6P/mSzHgBYImb7rIlrUk
aEWbEs4rAi0i8cwlg313ASK35E5enKM0C9uPaqnmFUQlT8X9SD+ELB7qHGRaXjcr
rd1HBuFu2bxJm6Tcfmy4bf+6QYW5czg1mJpGjvM9zCVHDtBxVj71XvVM6MLIruYn
zvNHq6ia8y1XUfkCxE5pzb0ap0LSS2XIEZxdRUCapGLAg4GNiA3Zkq4aDt8s7rGJ
fARzsx7PrOF3TgCxF97GZhRU6chMK8YAChRfwqsg0Mpw2plqiYa9v99KrRwPdzJo
7J8M8tAQhZB8YzG0U4Dsvb6odc8OYAFJTPpFvNjyQGgcjWudp6vo0YbK54z/z5s4
-----END RSA PRIVATE KEY-----`)
