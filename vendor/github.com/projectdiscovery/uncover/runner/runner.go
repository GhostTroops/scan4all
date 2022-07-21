package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/stringsutil"
	"github.com/projectdiscovery/uncover/uncover"
	"github.com/projectdiscovery/uncover/uncover/agent/censys"
	"github.com/projectdiscovery/uncover/uncover/agent/fofa"
	"github.com/projectdiscovery/uncover/uncover/agent/shodan"
	"github.com/projectdiscovery/uncover/uncover/agent/shodanidb"
	"go.uber.org/ratelimit"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// Runner is an instance of the uncover enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options *Options
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{options: options}
	return runner, nil
}

// RunEnumeration runs the subdomain enumeration flow on the targets specified
func (r *Runner) Run(ctx context.Context, query ...string) error {
	if !r.options.Provider.HasKeys() && !r.options.hasAnyAnonymousProvider() {
		return errors.New("no keys provided")
	}

	var censysRateLimiter, fofaRateLimiter, shodanRateLimiter, shodanIdbRateLimiter ratelimit.Limiter
	if r.options.Delay > 0 {
		censysRateLimiter = ratelimit.New(1, ratelimit.Per(r.options.delay))
		fofaRateLimiter = ratelimit.New(1, ratelimit.Per(r.options.delay))
		shodanRateLimiter = ratelimit.New(1, ratelimit.Per(r.options.delay))
		shodanIdbRateLimiter = ratelimit.New(1024) // seems a reasonable upper limit
	} else {
		censysRateLimiter = ratelimit.NewUnlimited()
		fofaRateLimiter = ratelimit.NewUnlimited()
		shodanRateLimiter = ratelimit.NewUnlimited()
		shodanIdbRateLimiter = ratelimit.NewUnlimited()
	}

	var agents []uncover.Agent
	// declare clients
	for _, engine := range r.options.Engine {
		var (
			agent uncover.Agent
			err   error
		)
		switch engine {
		case "shodan":
			agent, err = shodan.NewWithOptions(&uncover.AgentOptions{RateLimiter: shodanRateLimiter})
		case "censys":
			agent, err = censys.NewWithOptions(&uncover.AgentOptions{RateLimiter: censysRateLimiter})
		case "fofa":
			agent, err = fofa.NewWithOptions(&uncover.AgentOptions{RateLimiter: fofaRateLimiter})
		case "shodan-idb":
			agent, err = shodanidb.NewWithOptions(&uncover.AgentOptions{RateLimiter: shodanIdbRateLimiter})
		default:
			err = errors.New("unknown agent type")
		}
		if err != nil {
			return err
		}
		agents = append(agents, agent)
	}

	// open the output file - always overwrite
	outputWriter, err := NewOutputWriter()
	if err != nil {
		return err
	}
	outputWriter.AddWriters(os.Stdout)
	if r.options.OutputFile != "" {
		outputFile, err := os.Create(r.options.OutputFile)
		if err != nil {
			return err
		}
		defer outputFile.Close()
		outputWriter.AddWriters(outputFile)
	}

	// enumerate
	var wg sync.WaitGroup

	for _, q := range query {
		uncoverQuery := &uncover.Query{
			Query: q,
			Limit: r.options.Limit,
		}
		for _, agent := range agents {
			// skip all agents for pure ips/cidrs
			if shouldSkipForAgent(agent, uncoverQuery) {
				continue
			}
			wg.Add(1)
			go func(agent uncover.Agent, uncoverQuery *uncover.Query) {
				defer wg.Done()
				keys := r.options.Provider.GetKeys()
				if keys.Empty() && agent.Name() != "shodan-idb" {
					gologger.Error().Label(agent.Name()).Msgf("empty keys\n")
					return
				}
				session, err := uncover.NewSession(&keys, r.options.Timeout)
				if err != nil {
					gologger.Error().Label(agent.Name()).Msgf("couldn't create new session: %s\n", err)
				}
				ch, err := agent.Query(session, uncoverQuery)
				if err != nil {
					gologger.Warning().Msgf("%s\n", err)
					return
				}
				for result := range ch {
					result.Timestamp = time.Now().Unix()
					switch {
					case result.Error != nil:
						gologger.Warning().Label(agent.Name()).Msgf("%s\n", result.Error.Error())
					case r.options.JSON:
						data, err := json.Marshal(result)
						if err != nil {
							continue
						}
						gologger.Verbose().Label(agent.Name()).Msgf("%s\n", string(data))
						outputWriter.Write(data)
					case r.options.Raw:
						gologger.Verbose().Label(agent.Name()).Msgf("%s\n", result.RawData())
						outputWriter.WriteString(result.RawData())
					default:
						port := fmt.Sprint(result.Port)
						replacer := strings.NewReplacer(
							"ip", result.IP,
							"host", result.Host,
							"port", port,
						)
						outData := replacer.Replace(r.options.OutputFields)
						searchFor := []string{result.IP, port}
						if result.Host != "" {
							searchFor = append(searchFor, result.Host)
						}
						// send to output if any of the field got replaced
						if stringsutil.ContainsAny(outData, searchFor...) {
							gologger.Verbose().Label(agent.Name()).Msgf("%s\n", outData)
							outputWriter.WriteString(outData)
						}
					}

				}
			}(agent, uncoverQuery)
		}
	}

	wg.Wait()
	return nil
}

func shouldSkipForAgent(agent uncover.Agent, uncoverQuery *uncover.Query) bool {
	return (iputil.IsIP(uncoverQuery.Query) || iputil.IsCIDR(uncoverQuery.Query)) && agent.Name() != "shodan-idb"
}
