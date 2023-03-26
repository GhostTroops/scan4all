package engine

import (
	"bytes"
	"context"
	"fmt"
	"github.com/asaskevich/govalidator"
	"github.com/hktalent/ProScan4all/lib/util"
	"github.com/hktalent/ProScan4all/pocs_go"
	Const "github.com/hktalent/go-utils"
	"github.com/hktalent/jaeles/cmd"
	jsoniter "github.com/json-iterator/go"
	"github.com/karlseguin/ccache"
	"github.com/panjf2000/ants/v2"
	"github.com/projectdiscovery/iputil"
	"github.com/remeh/sizedwaitgroup"
	"github.com/ulule/deepcopier"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// 引擎对象，全局单实例
type Engine struct {
	Context      *context.Context               // 上下文
	Wg           *sizedwaitgroup.SizedWaitGroup // Wg
	Pool         int                            // 线程池
	PoolFunc     *ants.PoolWithFunc             // 线程调用
	EventData    chan *Const.EventData          // 数据队列
	NodeId       string                         `json:"node_id"`    // 分布式引擎节点的id，除非系统更换，docker重制，否则始终一致
	LimitTask    int                            `json:"limit_task"` // 当前节点任务并发数的限制
	SyTask       int                            `json:"sy_task"`    // 剩余task
	DtServer     string                         `json:"dt_server"`  // 获取任务、提交任务状态的server
	caseScanFunc sync.Map
	Lock         *sync.Mutex
	mcc          *ccache.Cache // 内存缓存
}

var GEngine *Engine

// 获取分布式任务
// /api/v1.0/syncResult/task/

// 创建引擎
//
//	默认每个 goroutine 占用 8KB 内存
//	一台 8GB 内存的机器满打满算也只能创建 8GB/8KB = 1000000 个 goroutine
//	更何况系统还需要保留一部分内存运行日常管理任务，go 运行时需要内存运行 gc、处理 goroutine 切换等
func NewEngine(c *context.Context, pool int) *Engine {
	if nil != util.G_Engine {
		return util.G_Engine.(*Engine)
	}
	x1 := &Engine{
		mcc:       util.GetMemoryCache(100000, nil),
		Lock:      &sync.Mutex{},
		Context:   c,
		Wg:        util.GetWg(util.GetValAsInt("WgThread", 64)),
		Pool:      pool,
		DtServer:  util.GetVal("DtServer"),
		EventData: make(chan *Const.EventData, pool),
		LimitTask: util.GetValAsInt("LimitTask", 4),
	}
	x1.SyTask = x1.LimitTask // 初始化剩余任务等于最大任务数
	x1.initNodeId()
	p, err := ants.NewPoolWithFunc(pool, func(i interface{}) {
		defer x1.Wg.Done()
		x1.DoEvent(i.(*Const.EventData))
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

// 优化使用websocket、或者webRTC
// "https://dt.51pwn.com/api/v1.0/syncResult/task/%d"
// curl -v -XPOST -d '{"Num":22,"task_ids":"","node_id":"xx","task_num":443}'  https://127.0.0.1:8081/api/v1.0/syncResult/task/33
// 结果反馈 /api/v1.0/syncResult/task/%d
// 获取、确认分布式任务，Distributed Tasks
func (e *Engine) GetTask(okTaskIds string) {
	if resp, err := util.DoPost(fmt.Sprintf(e.DtServer, e.LimitTask), map[string]string{
		"Content-Type": "application/json",
	}, strings.NewReader(`{"Num":`+strconv.Itoa(e.SyTask)+`,"task_ids":"`+okTaskIds+`","node_id":"`+e.NodeId+`","task_num":`+strconv.Itoa(e.LimitTask)+`}`)); nil == err && nil != resp {
		defer resp.Body.Close()
		var n1 = Const.EventData{}
		var oTsk = map[string]interface{}{}
		if data, err := ioutil.ReadAll(resp.Body); nil == err {
			if err := json.Unmarshal(data, &oTsk); nil == err {
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

var reTsk1 = regexp.MustCompile(`[\n]`)

// 目标类型
// 去除私有网络的扫描任务
// 第一个私有网络，第二个是互联网目标
func (e *Engine) FixTask(s string) (string, string) {
	var a1, a2 []string
	if a := reTsk1.Split(s, -1); 0 < len(a) {
		for _, x := range a {
			if iputil.IsCidrWithExpansion(x) {
				x = strings.ReplaceAll(x, "-", "/")
				if ip1, _, err := net.ParseCIDR(x); nil == err {
					if ip1.IsPrivate() {
						a1 = append(a1, x)
					} else {
						a2 = append(a2, x)
					}
				}
			} else if ip1 := net.ParseIP(x); nil != ip1 {
				if ip1.IsPrivate() {
					a1 = append(a1, x)
				} else {
					a2 = append(a2, x)
				}
			} else if -1 < strings.Index(x, "://") {
				if govalidator.IsDNSName(x) {
					a2 = append(a2, x)
				} else if oU, err := url.Parse(x); nil == err {
					if ip1 := net.ParseIP(oU.Hostname()); nil != ip1 {
						if ip1.IsPrivate() {
							a1 = append(a1, x)
						} else {
							a2 = append(a2, x)
						}
					}
				}
			} else { // 域名的情况
				a2 = append(a2, x)
			}
		}
	}
	return strings.Join(a1, "\n"), strings.Join(a2, "\n")
}

// 发送任务
//
//	全局参数配置 + 扫描类型，细化扫描项目，由多个节点来分担不同子任务
//	config：全局配置已经包含了扫描类型信息，开启、关闭各种类型扫描的参数，包含通过环境变量传递过来的控制
//	只发送非私有网络的任务
func (e *Engine) SendTask(s string) {
	_, s = e.FixTask(s)
	szUrl := fmt.Sprintf(e.DtServer, e.LimitTask)
	if oU, err := url.Parse(szUrl); nil == err {
		szUrl = strings.Join([]string{oU.Scheme, "://", oU.Host, "/api/v1.0/alipay_task"}, "")
		szSendData := ""
		sW := util.Base64Encode(s)
		szTaskId := e.generateTaskId(s)
		szSendData = "task_id=" + szTaskId + "&" + "scan_web=" + sW
		base64Str := util.GetSig(szSendData, prvKey)
		var oConf = map[string]interface{}{}
		deepcopier.Copy(util.GetAllConfig()).To(&oConf)
		delete(oConf, "DtServer")
		delete(oConf, "esUrl")
		delete(oConf, "Exploit")
		m1 := map[string]interface{}{"task_id": szTaskId, "op": "0", "data_sign": base64Str, "config": oConf}
		data, _ := json.Marshal(&m1)
		if resp, err := util.DoPost(fmt.Sprintf(e.DtServer, e.LimitTask), map[string]string{
			"Content-Type": "application/json",
		}, bytes.NewReader(data)); nil == err && nil != resp {
			defer resp.Body.Close()
			var n1 = Const.EventData{}
			if data, err := ioutil.ReadAll(resp.Body); nil == err {
				if err := json.Unmarshal(data, &n1); nil == err {
					e.SendEvent(&n1, n1.EventType)
				}
			}
		}
	}
}

// 注册特定类型的事件处理
func (e *Engine) EngineFuncFactory(nT uint64, fnCbk util.EngineFuncType) {
	e.RegCaseScanFunc(nT, fnCbk)
}

// 注册特定类型的事件处理
func (e *Engine) RegCaseScanFunc(nType uint64, fnCbk util.EngineFuncType) {
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

// 类型转换为 str tags
func (e *Engine) EventType2Str(argsTypes ...uint64) string {
	a := map[uint64]string{
		Const.ScanType_SSLInfo:         "sslInfo",         // 01- SSL信息分析，并对域名信息进行收集、进入下一步流程
		Const.ScanType_SubDomain:       "subdomain",       // 02- 子域名爆破，新域名回归 到:  1 <-- -> 2，做去重处理
		Const.ScanType_MergeIps:        "mergeIps",        // 03- 默认自动合并ip，记录ip与域名的关联关系，再发送payload时考虑：相同ip不同域名，相同payload分别发送 合并相同目标 若干域名的ip，避免扫描时重复
		Const.ScanType_WeakPassword:    "weakPassword",    // 04- 密码破解，隐含包含了: 端口扫描(05-masscan + 06-nmap)
		Const.ScanType_Masscan:         "masscan",         // 05- 合并后的ip 进行快速端口扫描
		Const.ScanType_Nmap:            "nmap",            // 06、精准 端口指纹，排除masscan已经识别的几种指纹
		Const.ScanType_IpInfo:          "ipInfo",          // 07- 获取ip info
		Const.ScanType_GoPoc:           "goPoc",           // 08- go-poc 检测, 隐含包含了: 端口扫描(05-masscan + 06-nmap)
		Const.ScanType_PortsWeb:        "portsWeb",        // 09- web端口识别，Naabu,识别 https，识别存活的web端口，再进入下一流程
		Const.ScanType_WebFingerprints: "webFingerprints", // 10- web指纹，识别蜜罐，并标识
		Const.ScanType_WebDetectWaf:    "webDetectWaf",    // 11- detect WAF
		Const.ScanType_WebScrapy:       "webScrapy",       // 12- 爬虫分析，form表单识别，字段名识别，form action提取；
		Const.ScanType_WebInfo:         "webInfo",         // 13- server、x-powerby、x***，url、ip、其他敏感信息（姓名、电话、地址、身份证）
		Const.ScanType_WebVulsScan:     "webVulsScan",     // 14- 包含 nuclei
		Const.ScanType_WebDirScan:      "webDirScan",      // 14- dir爆破,Gobuster
		Const.ScanType_Naabu:           "naabu",           // 15- naabu
		Const.ScanType_Httpx:           "httpx",           // 16- httpx
		Const.ScanType_DNSx:            "dnsx",            // 17- DNSX
		Const.ScanType_SaveEs:          "saveEs",          // 18- Save Es
		Const.ScanType_Jaeles:          "jaeles",          // 19 - jaeles
		Const.ScanType_Uncover:         "uncover",         // Uncover
		Const.ScanType_Ffuf:            "ffuf",            // ffuf
		Const.ScanType_Amass:           "amass",           // amass
		Const.ScanType_Subfinder:       "subfinder",       // subfinder
		Const.ScanType_Shuffledns:      "shuffledns",      // shuffledns
		Const.ScanType_Tlsx:            "tlsx",            // tlsx
		Const.ScanType_Katana:          "katana",          // katana
		Const.ScanType_Nuclei:          "nuclei",          // nuclei
		Const.ScanType_Gobuster:        "gobuster",        // Gobuster
	}
	var oR []string
	for _, i := range argsTypes {
		for k, v := range a {
			if int64(i&k) == int64(k) {
				oR = append(oR, v)
			}
		}
	}
	return strings.Join(oR, ",")
}

// 关联发送若干个事件
func (e *Engine) SendEvent(evt *Const.EventData, argsTypes ...uint64) {
	for _, i := range argsTypes {
		var n1 = Const.EventData{}
		deepcopier.Copy(evt).To(&n1)
		n1.EventType = i
		e.EventData <- &n1
	}
}

// 7天
var ScanTargetNoRepeatCc = time.Minute * 60 * 24 * 7

// 分派任务
//
//	1-加锁，避免多个任务并发冲突
//	2-获取参数做key + type，避免重复执行
func (e *Engine) Dispather(ed *Const.EventData) {
	e.Lock.Lock()
	defer e.Lock.Unlock()
	oR := e.GetCaseScanFunc()
	bNo := true
	oR.Range(func(k, v any) bool {
		t1 := k.(uint64)
		if t1&ed.EventType == t1 {
			bNo = false
			log.Println("Dispather ", Const.GetTypeName(t1), ed.EventData)
			if 0 == len(ed.EventData) || fmt.Sprintf("%v", ed.EventData[0]) == "" {
				log.Println("No correct parameters ", Const.GetTypeName(t1))
				return true
			}
			szKey := fmt.Sprintf("%s_%s", Const.GetTypeName(t1), util.GetSha1(ed.EventData))
			if nil == e.mcc.Get(szKey) {
				e.mcc.Set(szKey, "", ScanTargetNoRepeatCc)
				v.(util.EngineFuncType)(ed, ed.EventData...)
			}
		}
		return true
	})
	if bNo {
		log.Println("not found event type")
	}
}

// 执行事件代码 内部用
//
//	每个事件自己做防重处理
//	每个事件异步执行
//	每种事件类型可以独立控制并发数
func (e *Engine) DoEvent(ed *Const.EventData) {
	if nil != ed && nil != ed.EventData && 0 < len(ed.EventData) {
		e.Dispather(ed)
	}
}

func (x1 *Engine) Running() {
	// 异步启动一个线程处理检测，避免
	util.DoSyncFunc(func() {
		defer func() {
			x1.Close()
		}()
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		//nMax := 120 // 等xxx秒都没有消息进入就退出
		//nCnt := 0
		// 每10秒获取一次任务
		c1Task := time.NewTicker(5 * time.Second)  // 获取分布式任务
		c2Task := time.NewTicker(15 * time.Second) // 延时清理
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
					x1.Wg.Add()
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
				//default:
				//util.DoSleep()
			}
		}
	})
}

// 引擎总入口
func init() {
	//log.Println("engineImp.go run")
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
