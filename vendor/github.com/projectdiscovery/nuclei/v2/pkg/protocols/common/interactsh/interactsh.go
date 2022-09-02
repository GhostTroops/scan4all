package interactsh

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/karlseguin/ccache"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/writer"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Client is a wrapped client for interactsh server.
type Client struct {
	// interactsh is a client for interactsh server.
	interactsh *client.Client
	// requests is a stored cache for interactsh-url->request-event data.
	requests *ccache.Cache
	// interactions is a stored cache for interactsh-interaction->interactsh-url data
	interactions *ccache.Cache
	// matchedTemplates is a stored cache to track matched templates
	matchedTemplates *ccache.Cache
	// interactshURLs is a stored cache to track track multiple interactsh markers
	interactshURLs *ccache.Cache

	options          *Options
	eviction         time.Duration
	pollDuration     time.Duration
	cooldownDuration time.Duration

	hostname       string
	firstTimeGroup sync.Once
	generated      uint32 // decide to wait if we have a generated url
	matched        bool
	IsClosed bool
}

var (
	defaultInteractionDuration = 60 * time.Second
	interactshURLMarkerRegex   = regexp.MustCompile(`{{interactsh-url(?:_[0-9]+){0,3}}}`)
)

const (
	stopAtFirstMatchAttribute = "stop-at-first-match"
	templateIdAttribute = "template-id"
)

// Options contains configuration options for interactsh nuclei integration.
type Options struct {
	// ServerURL is the URL of the interactsh server.
	ServerURL string
	// Authorization is the Authorization header value
	Authorization string
	// CacheSize is the numbers of requests to keep track of at a time.
	// Older items are discarded in LRU manner in favor of new requests.
	CacheSize int64
	// Eviction is the period of time after which to automatically discard
	// interaction requests.
	Eviction time.Duration
	// CooldownPeriod is additional time to wait for interactions after closing
	// of the poller.
	CooldownPeriod time.Duration
	// PollDuration is the time to wait before each poll to the server for interactions.
	PollDuration time.Duration
	// Output is the output writer for nuclei
	Output output.Writer
	// IssuesClient is a client for issue exporting
	IssuesClient *reporting.Client
	// Progress is the nuclei progress bar implementation.
	Progress progress.Progress
	// Debug specifies whether debugging output should be shown for interactsh-client
	Debug         bool
	DebugRequest  bool
	DebugResponse bool
	// DisableHttpFallback controls http retry in case of https failure for server url
	DisableHttpFallback bool
	// NoInteractsh disables the engine
	NoInteractsh bool
	// NoColor dissbles printing colors for matches
	NoColor bool

	StopAtFirstMatch bool
	HTTPClient       *retryablehttp.Client
}

const defaultMaxInteractionsCount = 5000

// New returns a new interactsh server client
func New(options *Options) (*Client, error) {
	configure := ccache.Configure()
	configure = configure.MaxSize(options.CacheSize)
	cache := ccache.New(configure)

	interactionsCfg := ccache.Configure()
	interactionsCfg = interactionsCfg.MaxSize(defaultMaxInteractionsCount)
	interactionsCache := ccache.New(interactionsCfg)

	matchedTemplateCache := ccache.New(ccache.Configure().MaxSize(defaultMaxInteractionsCount))
	interactshURLCache := ccache.New(ccache.Configure().MaxSize(defaultMaxInteractionsCount))

	interactClient := &Client{
		IsClosed:false,
		eviction:         options.Eviction,
		interactions:     interactionsCache,
		matchedTemplates: matchedTemplateCache,
		interactshURLs:   interactshURLCache,
		options:          options,
		requests:         cache,
		pollDuration:     options.PollDuration,
		cooldownDuration: options.CooldownPeriod,
	}
	return interactClient, nil
}

// NewDefaultOptions returns the default options for interactsh client
func NewDefaultOptions(output output.Writer, reporting *reporting.Client, progress progress.Progress) *Options {
	return &Options{
		ServerURL:           client.DefaultOptions.ServerURL,
		CacheSize:           5000,
		Eviction:            60 * time.Second,
		CooldownPeriod:      5 * time.Second,
		PollDuration:        5 * time.Second,
		Output:              output,
		IssuesClient:        reporting,
		Progress:            progress,
		DisableHttpFallback: true,
		NoColor:             false,
	}
}

func (c *Client) firstTimeInitializeClient() error {
	if c.options.NoInteractsh ||nil == c.requests||nil == c.matchedTemplates||nil == c.interactions||c.IsClosed{
		return nil // do not init if disabled
	}
	interactsh, err := client.New(&client.Options{
		ServerURL:           c.options.ServerURL,
		Token:               c.options.Authorization,
		DisableHTTPFallback: c.options.DisableHttpFallback,
		HTTPClient:          c.options.HTTPClient,
	})
	if err != nil {
		return errors.Wrap(err, "could not create client")
	}
	c.interactsh = interactsh

	interactURL := interactsh.URL()
	interactDomain := interactURL[strings.Index(interactURL, ".")+1:]
	gologger.Info().Msgf("Using Interactsh Server: %s", interactDomain)
	c.hostname = interactDomain

	interactsh.StartPolling(c.pollDuration, func(interaction *server.Interaction) {
		item := c.requests.Get(interaction.UniqueID)

		if item == nil {
			// If we don't have any request for this ID, add it to temporary
			// lru cache, so we can correlate when we get an add request.
			gotItem := c.interactions.Get(interaction.UniqueID)
			if gotItem == nil {
				c.interactions.Set(interaction.UniqueID, []*server.Interaction{interaction}, defaultInteractionDuration)
			} else if items, ok := gotItem.Value().([]*server.Interaction); ok {
				items = append(items, interaction)
				c.interactions.Set(interaction.UniqueID, items, defaultInteractionDuration)
			}
			return
		}
		request, ok := item.Value().(*RequestData)
		if !ok {
			return
		}

		if _, ok := request.Event.InternalEvent[stopAtFirstMatchAttribute]; ok || c.options.StopAtFirstMatch {
			gotItem := c.matchedTemplates.Get(hash(request.Event.InternalEvent[templateIdAttribute].(string), request.Event.InternalEvent["host"].(string)))
			if gotItem != nil {
				return
			}
		}

		_ = c.processInteractionForRequest(interaction, request)
	})
	return nil
}

// processInteractionForRequest processes an interaction for a request
func (c *Client) processInteractionForRequest(interaction *server.Interaction, data *RequestData) bool {
	if c.IsClosed{return false}
	data.Event.InternalEvent["interactsh_protocol"] = interaction.Protocol
	data.Event.InternalEvent["interactsh_request"] = interaction.RawRequest
	data.Event.InternalEvent["interactsh_response"] = interaction.RawResponse
	data.Event.InternalEvent["interactsh_ip"] = interaction.RemoteAddress

	result, matched := data.Operators.Execute(data.Event.InternalEvent, data.MatchFunc, data.ExtractFunc, c.options.Debug || c.options.DebugRequest || c.options.DebugResponse)
	if !matched || result == nil {
		return false // if we don't match, return
	}
	c.requests.Delete(interaction.UniqueID)

	if data.Event.OperatorsResult != nil {
		data.Event.OperatorsResult.Merge(result)
	} else {
		data.Event.OperatorsResult = result
	}
	data.Event.Results = data.MakeResultFunc(data.Event)
	for _, event := range data.Event.Results {
		event.Interaction = interaction
	}

	if c.options.Debug || c.options.DebugRequest || c.options.DebugResponse {
		c.debugPrintInteraction(interaction, data.Event.OperatorsResult)
	}

	if writer.WriteResult(data.Event, c.options.Output, c.options.Progress, c.options.IssuesClient) {
		c.matched = true
		if _, ok := data.Event.InternalEvent[stopAtFirstMatchAttribute]; ok || c.options.StopAtFirstMatch {
			c.matchedTemplates.Set(hash(data.Event.InternalEvent[templateIdAttribute].(string), data.Event.InternalEvent["host"].(string)), true, defaultInteractionDuration)
		}
	}
	return true
}

// URL returns a new URL that can be interacted with
func (c *Client) URL() string {
	c.firstTimeGroup.Do(func() {
		if err := c.firstTimeInitializeClient(); err != nil {
			gologger.Error().Msgf("Could not initialize interactsh client: %s", err)
		}
	})
	if c.IsClosed|| c.interactsh == nil {
		return ""
	}
	atomic.CompareAndSwapUint32(&c.generated, 0, 1)
	return c.interactsh.URL()
}

// Close closes the interactsh clients after waiting for cooldown period.
func (c *Client) Close() bool {
	c.IsClosed = true
	defer func() {
		if nil != c.interactions {
			c.interactions.Clear()
			c.interactions.Stop()
			c.interactions = nil
		}
		if nil != c.requests {
			c.requests.Clear()
			c.requests.Stop()
			c.requests = nil
		}
		if nil != c.matchedTemplates {
			c.matchedTemplates.Clear()
			c.matchedTemplates.Stop()
			c.matchedTemplates = nil
		}
		if nil != c.interactshURLs {
			c.interactshURLs.Clear()
			c.interactshURLs.Stop()
			c.interactshURLs = nil
		}
	}()
	if c.cooldownDuration > 0 && atomic.LoadUint32(&c.generated) == 1 {
		time.Sleep(c.cooldownDuration)
	}
	if c.interactsh != nil {
		c.interactsh.StopPolling()
		c.interactsh.Close()
	}
	return c.matched
}

// ReplaceMarkers replaces the {{interactsh-url}} placeholders to actual
// URLs pointing to interactsh-server.
//
// It accepts data to replace as well as the URL to replace placeholders
// with generated uniquely for each request.
func (c *Client) ReplaceMarkers(data string, interactshURLs []string) (string, []string) {
	if nil == c.interactshURLs||c.IsClosed{return data,interactshURLs}
	for interactshURLMarkerRegex.Match([]byte(data)) {
		url := c.URL()
		interactshURLs = append(interactshURLs, url)
		interactshURLMarker := interactshURLMarkerRegex.FindString(data)
		if interactshURLMarker != "" {
			data = strings.Replace(data, interactshURLMarker, url, 1)
			urlIndex := strings.Index(url, ".")
			if urlIndex == -1 {
				continue
			}
			c.interactshURLs.Set(url, interactshURLMarker, defaultInteractionDuration)
		}
	}
	return data, interactshURLs
}

// MakePlaceholders does placeholders for interact URLs and other data to a map
func (c *Client) MakePlaceholders(urls []string, data map[string]interface{}) {
	if c.IsClosed{return}
	data["interactsh-server"] = c.hostname
	if nil == c.interactshURLs{return }
	for _, url := range urls {
		if interactshURLMarker := c.interactshURLs.Get(url); interactshURLMarker != nil {
			if interactshURLMarker, ok := interactshURLMarker.Value().(string); ok {
				interactshMarker := strings.TrimSuffix(strings.TrimPrefix(interactshURLMarker, "{{"), "}}")

				c.interactshURLs.Delete(url)

				data[interactshMarker] = url
				urlIndex := strings.Index(url, ".")
				if urlIndex == -1 {
					continue
				}
				data[strings.Replace(interactshMarker, "url", "id", 1)] = url[:urlIndex]
			}
		}
	}
}

// SetStopAtFirstMatch sets StopAtFirstMatch true for interactsh client options
func (c *Client) SetStopAtFirstMatch() {
	c.options.StopAtFirstMatch = true
}

// MakeResultEventFunc is a result making function for nuclei
type MakeResultEventFunc func(wrapped *output.InternalWrappedEvent) []*output.ResultEvent

// RequestData contains data for a request event
type RequestData struct {
	MakeResultFunc MakeResultEventFunc
	Event          *output.InternalWrappedEvent
	Operators      *operators.Operators
	MatchFunc      operators.MatchFunc
	ExtractFunc    operators.ExtractFunc
}

// RequestEvent is the event for a network request sent by nuclei.
func (c *Client) RequestEvent(interactshURLs []string, data *RequestData) {
	if nil==c.interactions||c.IsClosed{return}
	for _, interactshURL := range interactshURLs {
		id := strings.TrimRight(strings.TrimSuffix(interactshURL, c.hostname), ".")

		if _, ok := data.Event.InternalEvent[stopAtFirstMatchAttribute]; ok || c.options.StopAtFirstMatch {
			gotItem := c.matchedTemplates.Get(hash(data.Event.InternalEvent[templateIdAttribute].(string), data.Event.InternalEvent["host"].(string)))
			if gotItem != nil {
				break
			}
		}

		interaction := c.interactions.Get(id)
		if interaction != nil {
			// If we have previous interactions, get them and process them.
			interactions, ok := interaction.Value().([]*server.Interaction)
			if !ok {
				c.requests.Set(id, data, c.eviction)
				return
			}
			for _, interaction := range interactions {
				if c.processInteractionForRequest(interaction, data) {
					c.interactions.Delete(id)
					break
				}
			}
		} else {
			c.requests.Set(id, data, c.eviction)
		}
	}
}

// HasMatchers returns true if an operator has interactsh part
// matchers or extractors.
//
// Used by requests to show result or not depending on presence of interact.sh
// data part matchers.
func HasMatchers(op *operators.Operators) bool {
	if op == nil {
		return false
	}

	for _, matcher := range op.Matchers {
		for _, dsl := range matcher.DSL {
			if strings.Contains(dsl, "interactsh") {
				return true
			}
		}
		if strings.HasPrefix(matcher.Part, "interactsh") {
			return true
		}
	}
	for _, matcher := range op.Extractors {
		if strings.HasPrefix(matcher.Part, "interactsh") {
			return true
		}
	}
	return false
}

// HasMarkers checks if the text contains interactsh markers
func HasMarkers(data string) bool {
	return interactshURLMarkerRegex.Match([]byte(data))
}

func (c *Client) debugPrintInteraction(interaction *server.Interaction, event *operators.Result) {
	builder := &bytes.Buffer{}

	switch interaction.Protocol {
	case "dns":
		builder.WriteString(formatInteractionHeader("DNS", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp))
		if c.options.DebugRequest || c.options.Debug {
			builder.WriteString(formatInteractionMessage("DNS Request", interaction.RawRequest, event, c.options.NoColor))
		}
		if c.options.DebugResponse || c.options.Debug {
			builder.WriteString(formatInteractionMessage("DNS Response", interaction.RawResponse, event, c.options.NoColor))
		}
	case "http":
		builder.WriteString(formatInteractionHeader("HTTP", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp))
		if c.options.DebugRequest || c.options.Debug {
			builder.WriteString(formatInteractionMessage("HTTP Request", interaction.RawRequest, event, c.options.NoColor))
		}
		if c.options.DebugResponse || c.options.Debug {
			builder.WriteString(formatInteractionMessage("HTTP Response", interaction.RawResponse, event, c.options.NoColor))
		}
	case "smtp":
		builder.WriteString(formatInteractionHeader("SMTP", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp))
		if c.options.DebugRequest || c.options.Debug || c.options.DebugResponse {
			builder.WriteString(formatInteractionMessage("SMTP Interaction", interaction.RawRequest, event, c.options.NoColor))
		}
	case "ldap":
		builder.WriteString(formatInteractionHeader("LDAP", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp))
		if c.options.DebugRequest || c.options.Debug || c.options.DebugResponse {
			builder.WriteString(formatInteractionMessage("LDAP Interaction", interaction.RawRequest, event, c.options.NoColor))
		}
	}
	fmt.Fprint(os.Stderr, builder.String())
}

func formatInteractionHeader(protocol, ID, address string, at time.Time) string {
	return fmt.Sprintf("[%s] Received %s interaction from %s at %s", ID, protocol, address, at.Format("2006-01-02 15:04:05"))
}

func formatInteractionMessage(key, value string, event *operators.Result, noColor bool) string {
	value = responsehighlighter.Highlight(event, value, noColor, false)
	return fmt.Sprintf("\n------------\n%s\n------------\n\n%s\n\n", key, value)
}

func hash(templateID, host string) string {
	h := sha1.New()
	h.Write([]byte(templateID))
	h.Write([]byte(host))
	return hex.EncodeToString(h.Sum(nil))
}
