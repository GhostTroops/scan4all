package output

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	jsoniter "github.com/json-iterator/go"
	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/nuclei/v2/internal/colorizer"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
)

// Writer is an interface which writes output to somewhere for nuclei events.
type Writer interface {
	// Close closes the output writer interface
	Close()
	// Colorizer returns the colorizer instance for writer
	Colorizer() aurora.Aurora
	// Write writes the event to file and/or screen.
	Write(*ResultEvent) error
	// WriteFailure writes the optional failure event for template to file and/or screen.
	WriteFailure(event InternalEvent) error
	// Request logs a request in the trace log
	Request(templateID, url, requestType string, err error)
	//  WriteStoreDebugData writes the request/response debug data to file
	WriteStoreDebugData(host, templateID, eventType string, data string)
}

// StandardWriter is a writer writing output to file and screen for results.
type StandardWriter struct {
	json             bool
	jsonReqResp      bool
	noTimestamp      bool
	noMetadata       bool
	matcherStatus    bool
	mutex            *sync.Mutex
	aurora           aurora.Aurora
	outputFile       io.WriteCloser
	traceFile        io.WriteCloser
	errorFile        io.WriteCloser
	severityColors   func(severity.Severity) string
	storeResponse    bool
	storeResponseDir string
}

var decolorizerRegex = regexp.MustCompile(`\x1B\[[0-9;]*[a-zA-Z]`)

// InternalEvent is an internal output generation structure for nuclei.
type InternalEvent map[string]interface{}

// InternalWrappedEvent is a wrapped event with operators result added to it.
type InternalWrappedEvent struct {
	InternalEvent   InternalEvent
	Results         []*ResultEvent
	OperatorsResult *operators.Result
	UsesInteractsh  bool
}

// ResultEvent is a wrapped result event for a single nuclei output.
type ResultEvent struct {
	// Template is the relative filename for the template
	Template string `json:"template,omitempty"`
	// TemplateURL is the URL of the template for the result inside the nuclei
	// templates repository if it belongs to the repository.
	TemplateURL string `json:"template-url,omitempty"`
	// TemplateID is the ID of the template for the result.
	TemplateID string `json:"template-id"`
	// TemplatePath is the path of template
	TemplatePath string `json:"-"`
	// Info contains information block of the template for the result.
	Info model.Info `json:"info,inline"`
	// MatcherName is the name of the matcher matched if any.
	MatcherName string `json:"matcher-name,omitempty"`
	// ExtractorName is the name of the extractor matched if any.
	ExtractorName string `json:"extractor-name,omitempty"`
	// Type is the type of the result event.
	Type string `json:"type"`
	// Host is the host input on which match was found.
	Host string `json:"host,omitempty"`
	// Path is the path input on which match was found.
	Path string `json:"path,omitempty"`
	// Matched contains the matched input in its transformed form.
	Matched string `json:"matched-at,omitempty"`
	// ExtractedResults contains the extraction result from the inputs.
	ExtractedResults []string `json:"extracted-results,omitempty"`
	// Request is the optional, dumped request for the match.
	Request string `json:"request,omitempty"`
	// Response is the optional, dumped response for the match.
	Response string `json:"response,omitempty"`
	// Metadata contains any optional metadata for the event
	Metadata map[string]interface{} `json:"meta,omitempty"`
	// IP is the IP address for the found result event.
	IP string `json:"ip,omitempty"`
	// Timestamp is the time the result was found at.
	Timestamp time.Time `json:"timestamp"`
	// Interaction is the full details of interactsh interaction.
	Interaction *server.Interaction `json:"interaction,omitempty"`
	// CURLCommand is an optional curl command to reproduce the request
	// Only applicable if the report is for HTTP.
	CURLCommand string `json:"curl-command,omitempty"`
	// MatcherStatus is the status of the match
	MatcherStatus bool `json:"matcher-status"`
	// Lines is the line count for the specified match
	Lines []int `json:"matched-line"`

	FileToIndexPosition map[string]int `json:"-"`
}

// NewStandardWriter creates a new output writer based on user configurations
func NewStandardWriter(colors, noMetadata, noTimestamp, json, jsonReqResp, MatcherStatus, storeResponse bool, file, traceFile string, errorFile string, storeResponseDir string) (*StandardWriter, error) {
	auroraColorizer := aurora.NewAurora(colors)

	var outputFile io.WriteCloser
	if file != "" {
		output, err := newFileOutputWriter(file)
		if err != nil {
			return nil, errors.Wrap(err, "could not create output file")
		}
		outputFile = output
	}
	var traceOutput io.WriteCloser
	if traceFile != "" {
		output, err := newFileOutputWriter(traceFile)
		if err != nil {
			return nil, errors.Wrap(err, "could not create output file")
		}
		traceOutput = output
	}
	var errorOutput io.WriteCloser
	if errorFile != "" {
		output, err := newFileOutputWriter(errorFile)
		if err != nil {
			return nil, errors.Wrap(err, "could not create error file")
		}
		errorOutput = output
	}
	// Try to create output folder if it doesn't exist
	if storeResponse && !fileutil.FolderExists(storeResponseDir) {
		if err := fileutil.CreateFolder(storeResponseDir); err != nil {
			gologger.Fatal().Msgf("Could not create output directory '%s': %s\n", storeResponseDir, err)
		}
	}
	writer := &StandardWriter{
		json:             json,
		jsonReqResp:      jsonReqResp,
		noMetadata:       noMetadata,
		matcherStatus:    MatcherStatus,
		noTimestamp:      noTimestamp,
		aurora:           auroraColorizer,
		mutex:            &sync.Mutex{},
		outputFile:       outputFile,
		traceFile:        traceOutput,
		errorFile:        errorOutput,
		severityColors:   colorizer.New(auroraColorizer),
		storeResponse:    storeResponse,
		storeResponseDir: storeResponseDir,
	}
	return writer, nil
}

// Write writes the event to file and/or screen.
func (w *StandardWriter) Write(event *ResultEvent) error {
	// Enrich the result event with extra metadata on the template-path and url.
	if event.TemplatePath != "" {
		event.Template, event.TemplateURL = utils.TemplatePathURL(types.ToString(event.TemplatePath))
	}
	event.Timestamp = time.Now()

	var data []byte
	var err error

	if w.json {
		data, err = w.formatJSON(event)
	} else {
		data = w.formatScreen(event)
	}
	if err != nil {
		return errors.Wrap(err, "could not format output")
	}
	if len(data) == 0 {
		return nil
	}
	w.mutex.Lock()
	defer w.mutex.Unlock()

	_, _ = os.Stdout.Write(data)
	_, _ = os.Stdout.Write([]byte("\n"))

	if w.outputFile != nil {
		if !w.json {
			data = decolorizerRegex.ReplaceAll(data, []byte(""))
		}
		if _, writeErr := w.outputFile.Write(data); writeErr != nil {
			return errors.Wrap(err, "could not write to output")
		}
	}
	return nil
}

// JSONLogRequest is a trace/error log request written to file
type JSONLogRequest struct {
	Template string `json:"template"`
	Input    string `json:"input"`
	Error    string `json:"error"`
	Type     string `json:"type"`
}

// Request writes a log the requests trace log
func (w *StandardWriter) Request(templatePath, input, requestType string, requestErr error) {
	if w.traceFile == nil && w.errorFile == nil {
		return
	}
	request := &JSONLogRequest{
		Template: templatePath,
		Input:    input,
		Type:     requestType,
	}
	if unwrappedErr := utils.UnwrapError(requestErr); unwrappedErr != nil {
		request.Error = unwrappedErr.Error()
	} else {
		request.Error = "none"
	}

	data, err := jsoniter.Marshal(request)
	if err != nil {
		return
	}

	if w.traceFile != nil {
		_, _ = w.traceFile.Write(data)
	}

	if requestErr != nil && w.errorFile != nil {
		_, _ = w.errorFile.Write(data)
	}
}

// Colorizer returns the colorizer instance for writer
func (w *StandardWriter) Colorizer() aurora.Aurora {
	return w.aurora
}

// Close closes the output writing interface
func (w *StandardWriter) Close() {
	if w.outputFile != nil {
		w.outputFile.Close()
	}
	if w.traceFile != nil {
		w.traceFile.Close()
	}
	if w.errorFile != nil {
		w.errorFile.Close()
	}
}

// WriteFailure writes the failure event for template to file and/or screen.
func (w *StandardWriter) WriteFailure(event InternalEvent) error {
	if !w.matcherStatus {
		return nil
	}
	templatePath, templateURL := utils.TemplatePathURL(types.ToString(event["template-path"]))
	var templateInfo model.Info
	if event["template-info"] != nil {
		templateInfo = event["template-info"].(model.Info)
	}
	data := &ResultEvent{
		Template:      templatePath,
		TemplateURL:   templateURL,
		TemplateID:    types.ToString(event["template-id"]),
		TemplatePath:  types.ToString(event["template-path"]),
		Info:          templateInfo,
		Type:          types.ToString(event["type"]),
		Host:          types.ToString(event["host"]),
		MatcherStatus: false,
		Timestamp:     time.Now(),
	}
	return w.Write(data)
}
func sanitizeFileName(fileName string) string {
	fileName = strings.ReplaceAll(fileName, "http:", "")
	fileName = strings.ReplaceAll(fileName, "https:", "")
	fileName = strings.ReplaceAll(fileName, "/", "_")
	fileName = strings.ReplaceAll(fileName, "\\", "_")
	fileName = strings.ReplaceAll(fileName, "-", "_")
	fileName = strings.ReplaceAll(fileName, ".", "_")
	fileName = strings.TrimPrefix(fileName, "__")
	return fileName
}
func (w *StandardWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {
	if w.storeResponse {
		filename := sanitizeFileName(fmt.Sprintf("%s_%s", host, templateID))
		subFolder := filepath.Join(w.storeResponseDir, sanitizeFileName(eventType))
		if !fileutil.FolderExists(subFolder) {
			_ = fileutil.CreateFolder(subFolder)
		}
		filename = filepath.Join(subFolder, fmt.Sprintf("%s.txt", filename))
		f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, os.ModePerm)
		if err != nil {
			fmt.Print(err)
			return
		}
		_, _ = f.WriteString(fmt.Sprintln(data))
		f.Close()
	}

}
