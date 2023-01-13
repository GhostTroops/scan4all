package runner

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"io"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zlib"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"go.uber.org/atomic"
	"nuclei/v2/nuclei/runner/nucleicloud"
)

// runStandardEnumeration runs standard enumeration
func (r *Runner) runStandardEnumeration(executerOpts protocols.ExecuterOptions, store *loader.Store, engine *core.Engine) (*atomic.Bool, error) {
	if r.options.AutomaticScan {
		return r.executeSmartWorkflowInput(executerOpts, store, engine)
	}
	return r.executeTemplatesInput(store, engine)
}

// runCloudEnumeration runs cloud based enumeration
func (r *Runner) runCloudEnumeration(store *loader.Store, cloudTemplates, cloudTargets []string, nostore bool, limit int) (*atomic.Bool, error) {
	count := &atomic.Int64{}
	now := time.Now()
	defer func() {
		gologger.Info().Msgf("Scan execution took %s and found %d results", time.Since(now), count.Load())
	}()
	results := &atomic.Bool{}

	// TODO: Add payload file and workflow support for private templates
	catalogChecksums := nucleicloud.ReadCatalogChecksum()

	targets := make([]string, 0, r.hmapInputProvider.Count())
	r.hmapInputProvider.Scan(func(value *contextargs.MetaInput) bool {
		targets = append(targets, value.Input)
		return true
	})
	templates := make([]string, 0, len(store.Templates()))
	privateTemplates := make(map[string]string)

	for _, template := range store.Templates() {
		data, _ := os.ReadFile(template.Path)
		h := sha1.New()
		_, _ = io.Copy(h, bytes.NewReader(data))
		newhash := hex.EncodeToString(h.Sum(nil))

		templateRelativePath := getTemplateRelativePath(template.Path)
		if hash, ok := catalogChecksums[templateRelativePath]; ok || newhash == hash {
			templates = append(templates, templateRelativePath)
		} else {
			privateTemplates[filepath.Base(template.Path)] = gzipBase64EncodeData(data)
		}
	}

	taskID, err := r.cloudClient.AddScan(&nucleicloud.AddScanRequest{
		RawTargets:       targets,
		PublicTemplates:  templates,
		CloudTargets:     cloudTargets,
		CloudTemplates:   cloudTemplates,
		PrivateTemplates: privateTemplates,
		IsTemporary:      nostore,
		Filtering:        getCloudFilteringFromOptions(r.options),
	})
	if err != nil {
		return results, err
	}
	gologger.Info().Msgf("Created task with ID: %d", taskID)
	if nostore {
		gologger.Info().Msgf("Cloud scan storage: disabled")
	}
	time.Sleep(3 * time.Second)

	err = r.cloudClient.GetResults(taskID, true, limit, func(re *output.ResultEvent) {
		results.CompareAndSwap(false, true)
		_ = count.Inc()

		if outputErr := r.output.Write(re); outputErr != nil {
			gologger.Warning().Msgf("Could not write output: %s", err)
		}
		if r.issuesClient != nil {
			if err := r.issuesClient.CreateIssue(re); err != nil {
				gologger.Warning().Msgf("Could not create issue on tracker: %s", err)
			}
		}
	})
	return results, err
}

func getTemplateRelativePath(templatePath string) string {
	splitted := strings.SplitN(templatePath, "nuclei-templates", 2)
	if len(splitted) < 2 {
		return ""
	}
	return strings.TrimPrefix(splitted[1], "/")
}

func gzipBase64EncodeData(data []byte) string {
	var buf bytes.Buffer
	writer, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	_, _ = writer.Write(data)
	_ = writer.Close()
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	return encoded
}

func getCloudFilteringFromOptions(options *types.Options) *nucleicloud.AddScanRequestConfiguration {
	return &nucleicloud.AddScanRequestConfiguration{
		Authors:           options.Authors,
		Tags:              options.Tags,
		ExcludeTags:       options.ExcludeTags,
		IncludeTags:       options.IncludeTags,
		IncludeIds:        options.IncludeIds,
		ExcludeIds:        options.ExcludeIds,
		IncludeTemplates:  options.IncludeTemplates,
		ExcludedTemplates: options.ExcludedTemplates,
		ExcludeMatchers:   options.ExcludeMatchers,
		Severities:        options.Severities,
		ExcludeSeverities: options.ExcludeSeverities,
		Protocols:         options.Protocols,
		ExcludeProtocols:  options.ExcludeProtocols,
		IncludeConditions: options.IncludeConditions,
	}
}
