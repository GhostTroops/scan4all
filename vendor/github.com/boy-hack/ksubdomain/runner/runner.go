package runner

import (
	"context"
	"github.com/boy-hack/ksubdomain/core"
	"github.com/boy-hack/ksubdomain/core/device"
	"github.com/boy-hack/ksubdomain/core/gologger"
	"github.com/boy-hack/ksubdomain/core/options"
	"github.com/boy-hack/ksubdomain/runner/processbar"
	"github.com/boy-hack/ksubdomain/runner/result"
	"github.com/boy-hack/ksubdomain/runner/statusdb"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/phayes/freeport"
	"go.uber.org/ratelimit"
	"math"
	"math/rand"
	"strings"
	"time"
)

const (
	VerifyType = "verify"
	EnumType   = "enum"
	TestType   = "test"
)

type runner struct {
	hm              *statusdb.StatusDb
	options         *options.Options
	limit           ratelimit.Limiter
	handle          *pcap.Handle
	successIndex    uint64
	sendIndex       uint64
	recvIndex       uint64
	faildIndex      uint64
	sender          chan string
	recver          chan result.Result
	freeport        int
	dnsid           uint16      // dnsid 用于接收的确定ID
	maxRetry        int         // 最大重试次数
	timeout         int64       // 超时xx秒后重试
	fisrtloadChanel chan string // 数据加载完毕的chanel
	startTime       time.Time
	dnsType         layers.DNSType
}

func init() {
	rand.Seed(time.Now().Unix())
}
func New(opt *options.Options) (*runner, error) {
	var err error
	version := pcap.Version()
	r := new(runner)
	gologger.Infof(version + "\n")
	r.options = opt
	r.hm = statusdb.CreateMemoryDB()
	gologger.Infof("Default DNS:%s\n", core.SliceToString(opt.Resolvers))
	if len(opt.SpecialResolvers) > 0 {
		var keys []string
		for k, _ := range opt.SpecialResolvers {
			keys = append(keys, k)
		}
		gologger.Infof("Special DNS:%s\n", core.SliceToString(keys))
	}
	r.handle, err = device.PcapInit(opt.EtherInfo.Device)
	if err != nil {
		return nil, err
	}

	// 根据发包总数和timeout时间来分配每秒速度
	allPacket := opt.DomainTotal
	calcLimit := float64(allPacket/opt.TimeOut) * 0.85
	if calcLimit < 5000 {
		calcLimit = 5000
	}
	limit := int(math.Min(calcLimit, float64(opt.Rate)))
	r.limit = ratelimit.New(limit) // per second
	gologger.Infof("Domain Count:%d\n", r.options.DomainTotal)
	gologger.Infof("Rate:%dpps\n", limit)

	r.sender = make(chan string, 99)        // 协程发送缓冲
	r.recver = make(chan result.Result, 99) // 协程接收缓冲

	freePort, err := freeport.GetFreePort()
	if err != nil {
		return nil, err
	}
	r.dnsType, err = options.DnsType(opt.DnsType)
	if err != nil {
		return nil, err
	}
	r.freeport = freePort
	gologger.Infof("FreePort:%d\n", freePort)
	r.dnsid = 0x2021 // set dnsid 65500
	r.maxRetry = opt.Retry
	r.timeout = int64(opt.TimeOut)
	r.fisrtloadChanel = make(chan string)
	r.startTime = time.Now()
	return r, nil
}

func (r *runner) choseDns(domain string) string {
	dns := r.options.Resolvers
	specialDns := r.options.SpecialResolvers
	var selectDns string
	if specialDns != nil && len(specialDns) > 0 {
		for k, v := range specialDns {
			if strings.HasSuffix(domain, k) {
				dns = v
				break
			}
		}
	}
	selectDns = dns[rand.Intn(len(dns))]
	return selectDns
}

func (r *runner) printStatus() {
	queue := r.hm.Length()
	tc := int(time.Since(r.startTime).Seconds())
	data := &processbar.ProcessData{
		SuccessIndex: r.successIndex,
		SendIndex:    r.sendIndex,
		QueueLength:  queue,
		RecvIndex:    r.recvIndex,
		FaildIndex:   r.faildIndex,
		Elapsed:      tc,
	}
	if r.options.ProcessBar != nil {
		r.options.ProcessBar.WriteData(data)
	}
}
func (r *runner) RunEnumeration(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go r.recvChanel(ctx) // 启动接收线程
	go r.sendCycle()     // 发送线程
	go r.handleResult()  // 处理结果，打印输出
	go func() {
		for domain := range r.options.Domain {
			r.sender <- domain
		}
		r.fisrtloadChanel <- "ok"
	}()
	var isLoadOver bool = false // 是否加载文件完毕
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			r.printStatus()
			if isLoadOver {
				if r.hm.Length() <= 0 {
					gologger.Printf("\n")
					gologger.Infof("扫描完毕")
					return
				}
			}
		case <-r.fisrtloadChanel:
			go r.retry(ctx) // 遍历hm，依次重试
			isLoadOver = true
		case <-ctx.Done():
			return
		}
	}
}

func (r *runner) Close() {
	close(r.recver)
	close(r.sender)
	r.handle.Close()
	r.hm.Close()
	if r.options.ProcessBar != nil {
		r.options.ProcessBar.Close()
	}
}
