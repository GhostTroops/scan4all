package dns

import (
	"encoding/hex"
	"fmt"
	"net/url"

	"github.com/miekg/dns"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/vardump"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
	"github.com/projectdiscovery/retryabledns"
)

var _ protocols.Request = &Request{}

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.DNSProtocol
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input string, metadata /*TODO review unused parameter*/, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	// Parse the URL and return domain if URL.
	var domain string
	if utils.IsURL(input) {
		domain = extractDomain(input)
	} else {
		domain = input
	}

	var err error
	domain, err = request.parseDNSInput(domain)
	if err != nil {
		return errors.Wrap(err, "could not build request")
	}
	vars := GenerateVariables(domain)
	variablesMap := request.options.Variables.Evaluate(vars)
	vars = generators.MergeMaps(variablesMap, vars)

	if request.options.Options.Debug || request.options.Options.DebugRequests {
		gologger.Debug().Msgf("Protocol request variables: \n%s\n", vardump.DumpVariables(vars))
	}

	// Compile each request for the template based on the URL
	compiledRequest, err := request.Make(domain, vars)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, domain, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not build request")
	}

	dnsClient := request.dnsClient
	if varErr := expressions.ContainsUnresolvedVariables(request.Resolvers...); varErr != nil {
		if dnsClient, varErr = request.getDnsClient(request.options, metadata); varErr != nil {
			gologger.Warning().Msgf("[%s] Could not make dns request for %s: %v\n", request.options.TemplateID, domain, varErr)
			return nil
		}
	}

	requestString := compiledRequest.String()
	if varErr := expressions.ContainsUnresolvedVariables(requestString); varErr != nil {
		gologger.Warning().Msgf("[%s] Could not make dns request for %s: %v\n", request.options.TemplateID, domain, varErr)
		return nil
	}
	if request.options.Options.Debug || request.options.Options.DebugRequests || request.options.Options.StoreResponse {
		msg := fmt.Sprintf("[%s] Dumped DNS request for %s", request.options.TemplateID, domain)
		if request.options.Options.Debug || request.options.Options.DebugRequests {
			gologger.Info().Str("domain", domain).Msgf(msg)
			gologger.Print().Msgf("%s", requestString)
		}
		if request.options.Options.StoreResponse {
			request.options.Output.WriteStoreDebugData(domain, request.options.TemplateID, request.Type().String(), fmt.Sprintf("%s\n%s", msg, requestString))
		}
	}

	// Send the request to the target servers
	response, err := dnsClient.Do(compiledRequest)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, domain, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
	}
	if response == nil {
		return errors.Wrap(err, "could not send dns request")
	}
	request.options.Progress.IncrementRequests()

	request.options.Output.Request(request.options.TemplatePath, domain, request.Type().String(), err)
	gologger.Verbose().Msgf("[%s] Sent DNS request to %s\n", request.options.TemplateID, domain)

	// perform trace if necessary
	var traceData *retryabledns.TraceData
	if request.Trace {
		traceData, err = request.dnsClient.Trace(domain, request.question, request.TraceMaxRecursion)
		if err != nil {
			request.options.Output.Request(request.options.TemplatePath, domain, "dns", err)
		}
	}

	outputEvent := request.responseToDSLMap(compiledRequest, response, input, input, traceData)
	for k, v := range previous {
		outputEvent[k] = v
	}
	for k, v := range vars {
		outputEvent[k] = v
	}
	event := eventcreator.CreateEvent(request, outputEvent, request.options.Options.Debug || request.options.Options.DebugResponse)
	// TODO: dynamic values are not supported yet

	dumpResponse(event, request, request.options, response.String(), domain)
	if request.Trace {
		dumpTraceData(event, request.options, traceToString(traceData, true), domain)
	}

	callback(event)
	return nil
}

func (request *Request) parseDNSInput(host string) (string, error) {
	isIP := iputil.IsIP(host)
	switch {
	case request.question == dns.TypePTR && isIP:
		var err error
		host, err = dns.ReverseAddr(host)
		if err != nil {
			return "", err
		}
	default:
		if isIP {
			return "", errors.New("cannot use IP address as DNS input")
		}
		host = dns.Fqdn(host)
	}
	return host, nil
}

func dumpResponse(event *output.InternalWrappedEvent, request *Request, requestOptions *protocols.ExecuterOptions, response, domain string) {
	cliOptions := request.options.Options
	if cliOptions.Debug || cliOptions.DebugResponse || cliOptions.StoreResponse {
		hexDump := false
		if responsehighlighter.HasBinaryContent(response) {
			hexDump = true
			response = hex.Dump([]byte(response))
		}
		highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, response, cliOptions.NoColor, hexDump)
		msg := fmt.Sprintf("[%s] Dumped DNS response for %s\n\n%s", request.options.TemplateID, domain, highlightedResponse)
		if cliOptions.Debug || cliOptions.DebugResponse {
			gologger.Debug().Msg(msg)
		}
		if cliOptions.StoreResponse {
			request.options.Output.WriteStoreDebugData(domain, request.options.TemplateID, request.Type().String(), msg)
		}
	}
}

func dumpTraceData(event *output.InternalWrappedEvent, requestOptions *protocols.ExecuterOptions, traceData, domain string) {
	cliOptions := requestOptions.Options
	if cliOptions.Debug || cliOptions.DebugResponse {
		hexDump := false
		if responsehighlighter.HasBinaryContent(traceData) {
			hexDump = true
			traceData = hex.Dump([]byte(traceData))
		}
		highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, traceData, cliOptions.NoColor, hexDump)
		gologger.Debug().Msgf("[%s] Dumped DNS Trace data for %s\n\n%s", requestOptions.TemplateID, domain, highlightedResponse)
	}
}

// extractDomain extracts the domain name of a URL
func extractDomain(theURL string) string {
	u, err := url.Parse(theURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
