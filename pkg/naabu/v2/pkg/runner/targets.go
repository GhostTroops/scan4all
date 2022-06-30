package runner

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/asaskevich/govalidator"
	"github.com/hktalent/scan4all/pkg"
	"github.com/hktalent/scan4all/pkg/naabu/v2/pkg/privileges"
	"github.com/hktalent/scan4all/pkg/naabu/v2/pkg/scan"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ipranger"
	"github.com/projectdiscovery/iputil"
	"github.com/remeh/sizedwaitgroup"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
)

func (r *Runner) Load() error {
	r.scanner.State = scan.Init

	// merge all target sources into a file
	targetfile, err := r.mergeToFile()
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

func (r *Runner) mergeToFile() (string, error) {
	// merge all targets in a unique file
	tempInput, err := ioutil.TempFile("", "stdin-input-*")
	if err != nil {
		return "", err
	}
	defer tempInput.Close()

	// target defined via CLI argument
	if len(r.options.Host) > 0 {
		for _, v := range r.options.Host {
			if strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "http://") {
				if u, err := url.Parse(v); err == nil {
					fmt.Fprintf(tempInput, "%s\n", u.Hostname())
				}
			} else {
				fmt.Fprintf(tempInput, "%s\n", v)
			}
		}
	}

	// Targets from file
	if r.options.HostsFile != "" {
		f, err := os.Open(r.options.HostsFile)
		if err != nil {
			return "", err
		}
		defer f.Close()
		if _, err := io.Copy(tempInput, f); err != nil {
			return "", err
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

func (r *Runner) PreProcessTargets() error {
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
		func(target string) {
			defer wg.Done()
			// 处理ssl 数字证书中包含的域名信息，深度挖掘漏洞
			if "true" == pkg.GetVal("ParseSSl") {
				aH, err := pkg.DoDns(target)
				if nil == err && 0 < len(aH) {
					for _, x := range aH {
						gologger.Debug().Msg("add " + x)
						if err := r.AddTarget(x); err != nil {
							gologger.Warning().Msgf("%s\n", err)
						}
						r.DoDns(x)
					}
					return
				}
			}
			if err := r.AddTarget(target); err != nil {
				gologger.Warning().Msgf("%s\n", err)
			}
		}(s.Text())
	}

	wg.Wait()
	return nil
}

func Add2Naabubuffer(target string) {
	//log.Println("Add2Naabubuffer：", target)
	k1 := target + "_Add2Naabubuffer"
	if b1, err := pkg.Cache1.Get(k1); nil == err && string(b1) == target {
		log.Println("重复：", target)
		return
	}
	pkg.PutAny[string](k1, target)
	Naabubuffer.Write([]byte(target))
}

func (r *Runner) AddTarget(target string) error {
	k1 := target + "_AddTarget"
	if b1, err := pkg.Cache1.Get(k1); nil == err && string(b1) == target {
		log.Println("重复：", target)
		return nil
	}
	pkg.PutAny[string](k1, target)
	if target == "" {
		return nil
	} else if ipranger.IsCidr(target) {
		if r.options.Stream {
			r.streamChannel <- iputil.ToCidr(target)
		} else if err := r.scanner.IPRanger.AddHostWithMetadata(target, "cidr"); err != nil { // Add cidr directly to ranger, as single ips would allocate more resources later
			gologger.Warning().Msgf("%s\n", err)
		}
	} else if ipranger.IsIP(target) && !r.scanner.IPRanger.Contains(target) {
		if r.options.Stream {
			r.streamChannel <- iputil.ToCidr(target)
		} else if err := r.scanner.IPRanger.AddHostWithMetadata(target, "ip"); err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
	} else {
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			if u, err := url.Parse(target); err == nil {
				s1 := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
				Add2Naabubuffer(fmt.Sprintf("%s\n", s1))
				//Add2Naabubuffer(u.Hostname())
				// target 长度 大于 s1才处理
				////UrlPrecise     bool // 精准url扫描，不去除url清单上下文 2022-06-08
				UrlPrecise := pkg.GetVal(pkg.UrlPrecise)
				if "true" == UrlPrecise && len(target) > len(s1) {
					r1, err := regexp.Compile(`[^\/]`)
					if nil == err {
						s2 := r1.ReplaceAllString(target[len(s1):], "")
						// 包含1个以上/表示有上下文
						if 1 < len(s2) {
							if r.options.Verbose {
								log.Println("Precise scan: ", target)
							}
							Add2Naabubuffer(fmt.Sprintf("%s\n", target))
						}
					}
				}
				return nil
			}
		}
		r.DoDns(target)
	}

	return nil
}

func (r *Runner) DoDns(target string) {
	if govalidator.IsIP(target) {
		return
	}
	ips, err := r.resolveFQDN(target)
	if err != nil {
		return
	}
	for _, ip := range ips {
		if r.options.Stream {
			log.Println("Stream add ", ip)
			r.streamChannel <- iputil.ToCidr(ip)
		} else if err := r.scanner.IPRanger.AddHostWithMetadata(ip, target); err != nil {
			gologger.Warning().Msgf("%s\n", err)
		} else {
			log.Println(" r.scanner.IPRanger.AddHostWithMetadata add ", ip, " ", target)
		}
	}
}

func (r *Runner) resolveFQDN(target string) ([]string, error) {
	ips, err := r.host2ips(target)
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

	for _, hostIP := range hostIPS {
		gologger.Debug().Msgf("Using host %s for enumeration\n", hostIP)
		// dedupe all the hosts and also keep track of ip => host for the output - just append new hostname
		if err := r.scanner.IPRanger.AddHostWithMetadata(hostIP, target); err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
	}

	return hostIPS, nil
}
