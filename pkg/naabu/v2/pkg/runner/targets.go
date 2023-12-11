package runner

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg"
	"github.com/GhostTroops/scan4all/pkg/hydra"
	"github.com/GhostTroops/scan4all/pkg/naabu/v2/pkg/privileges"
	"github.com/GhostTroops/scan4all/pkg/naabu/v2/pkg/scan"
	"github.com/GhostTroops/scan4all/projectdiscovery/dnsxx"
	"github.com/asaskevich/govalidator"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/iputil"
	"github.com/remeh/sizedwaitgroup"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
)

func (r *Runner) Load() error {
	r.scanner.State = scan.Init

	// merge all target sources into a file
	targetfile, err := r.MergeToFile()
	if err != nil {
		return err
	}
	r.targetsFile = targetfile

	// pre-process all targets (resolves all non fqdn targets to ip address)
	err = r.PreProcessTargets()
	if err != nil {
		gologger.Warning().Msgf("%s\n", err)
	}

	return nil
}

func (r *Runner) MergeToFile() (string, error) {
	// merge all targets in a unique file
	tempInput, err := ioutil.TempFile("", "stdin-input-*")
	if err != nil {
		return "", err
	}
	defer tempInput.Close()

	// target defined via CLI argument
	if len(r.options.Host) > 0 {
		for _, v := range r.options.Host {
			if !util.HoneyportDetection(v) {
				if strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "http://") {
					if u, err := url.Parse(strings.TrimSpace(v)); err == nil {
						fmt.Fprintf(tempInput, "%s\n", u.Hostname())
					}
				} else {
					fmt.Fprintf(tempInput, "%s\n", v)
				}
			} else {
				log.Println("Honeypot found, skipped for you：", v)
			}
		}
	}

	// Targets from file
	if r.options.HostsFile != "" {
		if util.EnableHoneyportDetection {
			data, err := ioutil.ReadFile(r.options.HostsFile)
			if nil == err {
				a := strings.Split(strings.TrimSpace(string(data)), "\n")
				for _, x := range a {
					if !util.HoneyportDetection(x) {
						tempInput.WriteString(x + "\n")
					} else {
						log.Println("Honeypot found, skipped for you：", x)
					}
				}
			}
		} else {
			f, err := os.Open(r.options.HostsFile)
			if err != nil {
				return "", err
			}
			defer f.Close()
			if _, err := io.Copy(tempInput, f); err != nil {
				return "", err
			}
		}
	}

	// targets from STDIN
	if r.options.Stdin {
		if _, err := io.Copy(tempInput, os.Stdin); err != nil {
			return "", err
		}
	}

	// all additional non-named cli arguments are interpreted as targets
	for _, target := range flag.Args() {
		fmt.Fprintf(tempInput, "%s\n", target)
	}

	filename := tempInput.Name()
	return filename, nil
}

func (r *Runner) DoSsl(target string) []string {
	// 处理ssl 数字证书中包含的域名信息，深度挖掘漏洞
	if "true" == util.GetVal("ParseSSl") {
		aH, err := pkg.DoDns(target)
		if nil == err {
			return aH
		}
	}
	return []string{}
}

func (r *Runner) DoDns001(x string, aR []string) []string {
	aR = append(aR, r.DoDns2Ips(x)...)
	a1 := r.DoSsl(x)
	if 1 < len(a1) { // 如果只有1个是没有意义的，说明和x一样
		for _, j := range a1 {
			if j == x {
				continue
			}
			aR = append(aR, r.DoDns2Ips(j)...)
		}
		aR = append(aR, a1...)
	}
	if 1 == len(aR) { // 只有一个就直接用域名了，这样nmap的结果才能用
		aR = []string{x}
	} else {
		aR = append(aR, x)
	}
	return aR
}

// target域名转多个ip处理
func (r *Runner) DoTargets() (bool, error) {
	data, err := ioutil.ReadFile(r.targetsFile)
	if err != nil {
		return false, err
	}
	aR := []string{}
	a := strings.Split(string(data), "\n")
	for _, x := range a {
		// fix 无效的空行
		if 3 > len(x) {
			continue
		}
		if govalidator.IsDNSName(x) {
			aR = r.DoDns001(x, aR)
		} else if govalidator.IsURL(x) {
			if x1, err := url.Parse(strings.TrimSpace(x)); nil == err {
				if govalidator.IsDNSName(x) {
					aR = r.DoDns001(x, aR)
				} else {
					if "" == x1.Hostname() {
						aR = append(aR, x)
					} else {
						aR = append(aR, x1.Hostname())
					}
					continue
				}
			}
		}
		aR = append(aR, x)
	}
	a = nil
	aR = util.RemoveDuplication_map(aR)
	//log.Printf("DoTargets:: %+v", aR)
	if "" != r.targetsFile {
		err = ioutil.WriteFile(r.targetsFile, []byte(strings.Join(aR, "\n")), os.ModePerm)
		if nil != err {
			log.Println("ioutil.WriteFile(r.targetsFile err: ", err)
		}
	}
	// 有nmap那么就直接调用nmap了
	bRw := false
	if util.CheckHvNmap() {
		bRw = true
		tempInput1, err := ioutil.TempFile("", "stdin-out-*")
		if err == nil {
			defer tempInput1.Close()
			s009 := "/config/doNmapScan.sh "
			if runtime.GOOS == "windows" {
				s009 = "/config/doNmapScanWin.bat "
			}
			x := util.SzPwd + s009 + r.targetsFile + " " + tempInput1.Name()
			//log.Println(x)
			ss, err := util.DoCmd(strings.Split(x, " ")...)
			s0 := tempInput1.Name()
			if nil == err {
				if "" != ss {
					//	log.Println(ss, "\n")
				}
				if util.FileExists(s0) {
					//data, err := tempInput1.Stat()
					//log.Println(tempInput1.Name(), " file size: ", data.Size())
					//if nil == err && 100 < data.Size() {
					if x99, ok := util.TmpFile[string(util.Naabu)]; ok && 0 < len(x99) {
						defer func(f09 *os.File) {
							f09.Close()
							os.RemoveAll(f09.Name())
						}(x99[0])
					}
					util.TmpFile[string(util.Naabu)] = []*os.File{tempInput1}
					log.Println("start parse nmap xml result")
					hydra.DoNmapRst(&Naabubuffer)
					defer r.Close()
					if "" != r.targetsFile {
						ioutil.WriteFile(r.targetsFile, []byte(""), os.ModePerm)
					}
					log.Println("do namp over naabu ")
					return true, nil
					//} else {
					//	log.Println("tempInput1.Stat: ", err)
					//}
				} else {
					log.Println("nmap 结果文件不存在")
				}
			} else {
				log.Println("DoCmd: ", err)
			}
		} else {
			log.Println("ioutil.TempFile ", err)
		}
	} else {
		log.Println(" pkg.CheckHvNmap() false")
	}
	if bRw && "" != r.targetsFile {
		ioutil.WriteFile(r.targetsFile, []byte(strings.Join(aR, "\n")), os.ModePerm)
	}
	return false, nil
}

func (r *Runner) PreProcessTargets() error {
	if b11, _ := r.DoTargets(); b11 {
		return nil
	} else {
		log.Println("Start port scanning with naabu according to the configuration r.DoTargets")
	}
	if r.options.Stream {
		defer close(r.streamChannel)
	}
	wg := sizedwaitgroup.New(r.options.Threads)
	f, err := os.Open(r.targetsFile)
	if err != nil {
		return err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		wg.Add()
		go func(target string) {
			defer wg.Done()
			if err := r.AddTarget(target); err != nil {
				gologger.Warning().Msgf("%s\n", err)
			}
		}(s.Text())
	}
	wg.Wait()
	return nil
}
func Add2Naabubuffer(target string) {
	if strings.Contains(target, "://") {
		Add2Naabubuffer_1(target)
	} else if !strings.HasPrefix(target, "http") {
		Add2Naabubuffer_1("https://" + target)
		Add2Naabubuffer_1("http://" + target)
	}
}

func Add2Naabubuffer_1(target string) {
	// fix no http://
	if -1 == strings.Index(target, "://") {
		target = "http://" + target
	}
	//fmt.Println("Add2Naabubuffer：", target)
	k1 := target + "_Add2Naabubuffer"
	if b1, err := util.Cache1.Get(k1); nil == err && string(b1) == target {
		fmt.Println("重复：", target)
		return
	}
	util.PutAny[string](k1, target)
	// 缓存一下域名和ip的关系
	if oU, err := url.Parse(target); nil == err && oU.Hostname() != "" {
		dnsxx.DoGetDnsInfos(oU.Hostname())
	}
	Naabubuffer.Write([]byte(target))
}

var r1, _ = regexp.Compile(`[^\/]`)

func (r *Runner) AddTarget(target string) error {
	target = strings.TrimSpace(target)
	if "" == target {
		return nil
	}
	// fix to no http[s]:// no port
	if -1 < strings.Index(target, "://") {
		target = strings.Split(target, "://")[1]
	}
	if -1 < strings.Index(target, ":") {
		target = strings.Split(target, ":")[0]
	}
	//log.Println("target: ", target)
	k1 := target + "_AddTarget"
	if b1, err := util.Cache1.Get(k1); nil == err && string(b1) == target {
		log.Println("重复：", target)
		return nil
	}
	util.PutAny[string](k1, target)
	if target == "" {
		return nil
	} else if iputil.IsCIDR(target) {
		if r.options.Stream {
			r.streamChannel <- iputil.ToCidr(target)
		} else if err := r.scanner.IPRanger.AddHostWithMetadata(target, "cidr"); err != nil { // Add cidr directly to ranger, as single ips would allocate more resources later
			gologger.Warning().Msgf("%s\n", err)
		}
	} else if iputil.IsIP(target) && !r.scanner.IPRanger.Contains(target) {
		if r.options.Stream {
			r.streamChannel <- iputil.ToCidr(target)
		} else if err := r.scanner.IPRanger.AddHostWithMetadata(target, "ip"); err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
	} else {
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			if u, err := url.Parse(strings.TrimSpace(target)); err == nil {
				s1 := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
				Add2Naabubuffer(fmt.Sprintf("%s\n", s1))
				//Add2Naabubuffer(u.Hostname())
				// target 长度 大于 s1才处理
				////UrlPrecise     bool // 精准url扫描，不去除url清单上下文 2022-06-08
				UrlPrecise := util.GetVal(util.UrlPrecise)
				if "true" == UrlPrecise && len(target) > len(s1) {
					s2 := r1.ReplaceAllString(target[len(s1):], "")
					// 包含1个以上/表示有上下文
					if 1 < len(s2) {
						if r.options.Verbose {
							log.Println("Precise scan: ", target)
						}
						Add2Naabubuffer(fmt.Sprintf("%s\n", target))
					}

				}
				return nil
			}
		}
		r.DoDns(target)
	}

	return nil
}

func (r *Runner) DoDns2Ips(target string) []string {
	if govalidator.IsIP(target) {
		return []string{target}
	}
	ips, err := r.resolveFQDN(target)
	if err != nil {
		return []string{} // fixed #51
	}
	return ips
}

func (r *Runner) DoDns(target string) {
	if govalidator.IsIP(target) {
		return
	}
	ips := r.DoDns2Ips(target)
	for _, ip := range ips {
		if r.options.Stream {
			//log.Println("Stream add ", ip)
			r.streamChannel <- iputil.ToCidr(ip)
		} else if err := r.scanner.IPRanger.AddHostWithMetadata(ip, target); err != nil {
			gologger.Warning().Msgf("%s\n", err)
		} else {
			log.Println(" r.scanner.IPRanger.AddHostWithMetadata add ", ip, " ", target)
		}
		if ip == target && len(ip) != len(target) {
			log.Println("please reTry, Your current network is not good")
		}
	}
}

func (r *Runner) resolveFQDN(target string) ([]string, error) {
	ips, err := r.Host2ips(target)
	if err != nil {
		return []string{}, err
	}

	var (
		initialHosts []string
		hostIPS      []string
	)
	for _, ip := range ips {
		if !r.scanner.IPRanger.Np.ValidateAddress(ip) {
			gologger.Warning().Msgf("Skipping host %s as ip %s was excluded\n", target, ip)
			continue
		}

		initialHosts = append(initialHosts, ip)
	}

	if len(initialHosts) == 0 {
		return []string{}, nil
	}

	// If the user has specified ping probes, perform ping on addresses
	if privileges.IsPrivileged && r.options.Ping && len(initialHosts) > 1 {
		// Scan the hosts found for ping probes
		pingResults, err := scan.PingHosts(initialHosts)
		if err != nil {
			gologger.Warning().Msgf("Could not perform ping scan on %s: %s\n", target, err)
			return []string{}, err
		}
		for _, result := range pingResults.Hosts {
			if result.Type == scan.HostActive {
				gologger.Debug().Msgf("Ping probe succeed for %s: latency=%s\n", result.Host, result.Latency)
			} else {
				gologger.Debug().Msgf("Ping probe failed for %s: error=%s\n", result.Host, result.Error)
			}
		}

		// Get the fastest host in the list of hosts
		fastestHost, err := pingResults.GetFastestHost()
		if err != nil {
			gologger.Warning().Msgf("No active host found for %s: %s\n", target, err)
			return []string{}, err
		}
		gologger.Info().Msgf("Fastest host found for target: %s (%s)\n", fastestHost.Host, fastestHost.Latency)
		hostIPS = append(hostIPS, fastestHost.Host)
	} else if r.options.ScanAllIPS {
		hostIPS = initialHosts
	} else {
		hostIPS = append(hostIPS, initialHosts[0])
	}

	hostIPS = util.SliceRemoveDuplicates(hostIPS)
	for _, hostIP := range hostIPS {
		if r.mB[hostIP] {
			continue
		}
		r.mB[hostIP] = true
		gologger.Debug().Msgf("Using host %s for enumeration\n", hostIP)
		// dedupe all the hosts and also keep track of ip => host for the output - just append new hostname
		if err := r.scanner.IPRanger.AddHostWithMetadata(hostIP, target); err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
	}

	return hostIPS, nil
}
