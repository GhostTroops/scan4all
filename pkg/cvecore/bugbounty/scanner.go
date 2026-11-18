package bugbounty

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/GhostTroops/scan4all/pkg/cvecore/capture"
	"github.com/GhostTroops/scan4all/pkg/cvecore/fingerprint"
)

// Finding 与采集器的走私回放结果结构一致。
type Finding = capture.Finding

// recorder wraps every transport so exp requests can be fingerprinted and,
// when nothing succeeds, replayed through a smuggling channel.
var recorder = capture.NewRecorder(&http.Transport{Proxy: nil, DisableKeepAlives: true})

var client = &http.Client{
	Timeout:   10 * time.Second,
	Transport: recorder,
}

func Get(baseURL string) (int, string, http.Header, error) {
	resp, err := client.Get(baseURL)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	return resp.StatusCode, string(body), resp.Header, nil
}

type probeEntry struct {
	name string
	tags []string // required fingerprint components; empty = generic, always run
	fn   func(string) *Finding
}

// scanState keeps a target's fingerprint baseline so that components exposed by
// later exp / smuggling responses can trigger their own probes.
type scanState struct {
	base string
	key  string
	fpr  *fingerprint.Result
	ran  map[string]bool
}

var (
	statesMu   sync.Mutex
	scanStates = make(map[string]*scanState)
)

func resetScanStates() {
	statesMu.Lock()
	scanStates = make(map[string]*scanState)
	statesMu.Unlock()
}

func rememberState(st *scanState) {
	statesMu.Lock()
	scanStates[st.key] = st
	statesMu.Unlock()
}

func snapshotStates() []*scanState {
	statesMu.Lock()
	defer statesMu.Unlock()
	out := make([]*scanState, 0, len(scanStates))
	for _, st := range scanStates {
		out = append(out, st)
	}
	return out
}

// probeTable ties each probe to the fingerprint components it belongs to, so a
// recognised target only runs the matching exploits. Generic probes (leaks,
// config exposure) are not technology specific and always run. HTTP smuggling
// is not a first-pass probe: it is the zero-finding fallback that replays the
// payloads captured here.
var probeTable = []probeEntry{
	// Generic detection / exposure
	{"git", nil, ProbeGit},
	{"env", nil, ProbeEnv},
	{"debug", nil, ProbeDebug},
	{"git-leak", nil, ProbeGitLeak},

	// Component specific
	{"actuator", []string{"Spring"}, ProbeActuator},
	{"confluence", []string{"Confluence"}, ProbeConfluence},
	{"weblogic", []string{"WebLogic"}, ProbeWebLogic},
	{"jenkins", []string{"Jenkins"}, ProbeJenkins},
	{"kibana", []string{"Kibana", "Elasticsearch"}, ProbeKibana},
	{"git-platform", []string{"GitLab", "Gitea"}, ProbeGitPlatform},
	{"nacos", []string{"Nacos"}, ProbeNacos},
	{"skywalking", []string{"SkyWalking"}, ProbeSkyWalking},
	{"spring-cloud-function", []string{"Spring"}, ProbeCVE202222963},
	{"spring-gateway", []string{"Spring"}, ProbeSpringGateway},
	{"spring4shell", []string{"Spring"}, ProbeSpring4Shell},
	{"shiro", []string{"Shiro"}, ProbeShiro},
	{"s2-045", []string{"Struts2"}, ProbeS2045},
	{"s2-rest", []string{"Struts2"}, ProbeS2Rest},
	{"tomcat-put", []string{"Tomcat"}, ProbeTomcatPUT},
	{"tomcat-24813", []string{"Tomcat"}, ProbeTomcat24813},
	{"weblogic-14882", []string{"WebLogic"}, ProbeWebLogic14882},
	{"activemq", []string{"ActiveMQ"}, ProbeActiveMQ},
	{"cockpit", []string{"Cockpit"}, ProbeCockpit},
	{"dubbo", []string{"Dubbo"}, ProbeDubbo},
	{"fastjson", []string{"Fastjson"}, ProbeFastjson},
	{"thinkphp", []string{"ThinkPHP"}, ProbeThinkPHP},
	{"php-cgi", []string{"PHP"}, ProbeCVE20244577},
	{"phpunit", []string{"PHP"}, ProbeCVE20179841},
	{"metabase", []string{"Metabase"}, ProbeCVE202338646},
	{"papercut", []string{"PaperCut"}, ProbeCVE202327350},
}

func ScanTarget(target string, results chan<- *Finding, wg *sync.WaitGroup) {
	defer wg.Done()
	var urls []string
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		urls = []string{target}
	} else {
		urls = []string{"http://" + target, "https://" + target}
	}
	emit := func(f *Finding) { results <- f }

	for _, base := range urls {
		code, _, _, err := Get(base + "/")
		if err != nil || code == 0 {
			continue
		}

		// Fingerprint first: only run probes belonging to detected components.
		fpr := fingerprint.QuickDetect(base, 8*time.Second)
		if fpr.HasFingerprint() {
			fmt.Printf("[FP] %s → %s\n", base, fpr.Summary())
		} else {
			fmt.Printf("[FP] %s → none (%s), full blind set\n", base, fpr.Summary())
		}

		st := &scanState{
			base: base,
			key:  capture.KeyForBase(base),
			fpr:  fpr,
			ran:  make(map[string]bool),
		}
		recorder.MarkBaseline(st.key, fpr.Strong())
		rememberState(st)

		runProbes(st, emit, nil)
		expandFingerprint(st, emit)
		break // found working scheme, skip other
	}
}

// runProbes executes not-yet-run probes. only == nil means first pass (filter
// by the full fingerprint); otherwise only components discovered later are
// used, so a new fingerprint only adds its own probes.
func runProbes(st *scanState, emit func(*Finding), only []fingerprint.Match) {
	for _, p := range probeTable {
		if st.ran[p.name] {
			continue
		}
		if len(p.tags) > 0 {
			if only == nil {
				if !anyComponent(st.fpr, p.tags) {
					continue
				}
			} else if !tagsHit(only, p.tags) {
				continue
			}
		}
		st.ran[p.name] = true
		if f := p.fn(st.base); f != nil {
			emit(f)
		}
	}
}

// expandFingerprint merges components observed in exp responses since the
// baseline and runs the probes they map to (bounded to one extra round per
// discovery set; already-run probes are skipped by the ran set).
func expandFingerprint(st *scanState, emit func(*Finding)) {
	added := st.fpr.Merge(recorder.NewSinceBaseline(st.key))
	if len(added) == 0 {
		return
	}
	fmt.Printf("[FP+] %s → new fingerprint: %s; running mapped probes\n", st.base, matchSummary(added))
	runProbes(st, emit, added)
}

func matchSummary(matches []fingerprint.Match) string {
	var parts []string
	for _, m := range matches {
		s := m.Name
		if m.Version != "" {
			s += " " + m.Version
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

func anyComponent(fpr *fingerprint.Result, names []string) bool {
	for _, n := range names {
		if fpr.HasComponent(n) {
			return true
		}
	}
	return false
}

func tagsHit(matches []fingerprint.Match, tags []string) bool {
	for _, m := range matches {
		if m.Weak {
			continue
		}
		for _, t := range tags {
			if m.Name == t {
				return true
			}
		}
	}
	return false
}

func RunScan(targets []string, concurrency int) []*Finding {
	resetScanStates()

	results := make(chan *Finding, len(targets)*10)
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer func() { <-sem }()
			ScanTarget(target, results, &wg)
		}(t)
	}
	go func() { wg.Wait(); close(results) }()

	var findings []*Finding
	for f := range results {
		fmt.Printf("[%s] %s → %s\n", f.Severity, f.Vuln, f.URL)
		findings = append(findings, f)
	}

	// Second pass: only when nothing succeeded, replay every captured exp
	// payload once through a confirmed HTTP smuggling channel.
	replayed := false
	if len(findings) == 0 {
		buckets := recorder.TakeAll()
		if len(buckets) > 0 {
			fmt.Println("[*] No findings in the normal pass — replaying captured exp payloads through HTTP smuggling...")
			for _, f := range recorder.ReplayAll(buckets, 5*time.Second) {
				fmt.Printf("[%s] %s → %s\n", f.Severity, f.Vuln, f.URL)
				findings = append(findings, f)
			}
			replayed = true
		}
	}

	// Smuggled responses can expose a component the first fingerprint missed;
	// run the probes it maps to before returning.
	if replayed {
		for _, st := range snapshotStates() {
			before := len(findings)
			expandFingerprint(st, func(f *Finding) {
				fmt.Printf("[%s] %s → %s\n", f.Severity, f.Vuln, f.URL)
				findings = append(findings, f)
			})
			if len(findings) > before {
				fmt.Printf("[+] New fingerprint on %s added %d finding(s)\n", st.base, len(findings)-before)
			}
		}
	}
	return findings
}
