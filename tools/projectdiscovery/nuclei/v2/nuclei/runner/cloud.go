package runner

import (
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"nuclei/v2/nuclei/runner/nucleicloud"
)

// Get all the scan lists for a user/apikey.
func (r *Runner) getScanList(limit int) error {
	lastTime := "2099-01-02 15:04:05 +0000 UTC"
	header := []string{"ID", "Timestamp", "Targets", "Templates", "Matched", "Duration", "Status"}

	var (
		values [][]string
		count  int
	)
	for {
		items, err := r.cloudClient.GetScans(limit, lastTime)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			break
		}
		for _, v := range items {
			count++
			lastTime = v.CreatedAt.String()
			res := nucleicloud.PrepareScanListOutput(v)
			if r.options.JSON {
				_ = jsoniter.NewEncoder(os.Stdout).Encode(res)
			} else if !r.options.NoTables {
				values = append(values, []string{strconv.FormatInt(res.ScanID, 10), res.Timestamp, strconv.Itoa(res.Target), strconv.Itoa(res.Template), strconv.Itoa(res.ScanResult), res.ScanTime, res.ScanStatus})
			} else {
				gologger.Silent().Msgf("%d. [%s] [TARGETS: %d] [TEMPLATES: %d] [MATCHED: %d] [DURATION: %s] [STATUS: %s]\n", res.ScanID, res.Timestamp, res.Target, res.Template, res.ScanResult, res.ScanTime, strings.ToUpper(res.ScanStatus))

			}
		}
	}
	if count == 0 {
		return errors.New("no scan found")
	}
	if !r.options.NoTables {
		r.prettyPrintTable(header, values)
	}
	return nil
}

func (r *Runner) listDatasources() error {
	datasources, err := r.cloudClient.ListDatasources()
	if err != nil {
		return err
	}
	if len(datasources) == 0 {
		return errors.New("no cloud datasource found")
	}

	header := []string{"ID", "UpdatedAt", "Type", "Repo", "Path"}
	var values [][]string
	for _, source := range datasources {
		if r.options.JSON {
			_ = jsoniter.NewEncoder(os.Stdout).Encode(source)
		} else if !r.options.NoTables {
			values = append(values, []string{strconv.FormatInt(source.ID, 10), source.Updatedat.Format(nucleicloud.DDMMYYYYhhmmss), source.Type, source.Repo, source.Path})
		} else {
			gologger.Silent().Msgf("%d. [%s] [%s] [%s] %s", source.ID, source.Updatedat.Format(nucleicloud.DDMMYYYYhhmmss), source.Type, source.Repo, source.Path)
		}
	}
	if !r.options.NoTables {
		r.prettyPrintTable(header, values)
	}
	return nil
}

func (r *Runner) listTargets() error {
	items, err := r.cloudClient.ListTargets("")
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return errors.New("no target found")
	}

	header := []string{"ID", "Reference", "Count"}
	var values [][]string
	for _, source := range items {
		if r.options.JSON {
			_ = jsoniter.NewEncoder(os.Stdout).Encode(source)
		} else if !r.options.NoTables {
			values = append(values, []string{strconv.FormatInt(source.ID, 10), source.Reference, strconv.FormatInt(source.Count, 10)})
		} else {
			gologger.Silent().Msgf("%d. %s (%d)", source.ID, source.Reference, source.Count)
		}
	}
	if !r.options.NoTables {
		r.prettyPrintTable(header, values)
	}
	return nil
}

func (r *Runner) listTemplates() error {
	items, err := r.cloudClient.ListTemplates("")
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return errors.New("no template found")
	}

	header := []string{"ID", "Reference"}
	var values [][]string
	for _, source := range items {
		if r.options.JSON {
			_ = jsoniter.NewEncoder(os.Stdout).Encode(source)
		} else if !r.options.NoTables {
			values = append(values, []string{strconv.FormatInt(source.ID, 10), source.Reference})
		} else {
			gologger.Silent().Msgf("%d. %s", source.ID, source.Reference)
		}
	}
	if !r.options.NoTables {
		r.prettyPrintTable(header, values)
	}
	return nil
}

func (r *Runner) prettyPrintTable(header []string, values [][]string) {
	writer := tablewriter.NewWriter(os.Stdout)
	writer.SetHeader(header)
	writer.AppendBulk(values)
	writer.Render()
}

func (r *Runner) deleteScan(id string) error {
	ID, parseErr := strconv.ParseInt(id, 10, 64)
	if parseErr != nil {
		return errors.Wrap(parseErr, "could not parse scan id")
	}
	deleted, err := r.cloudClient.DeleteScan(ID)
	if err != nil {
		return errors.Wrap(err, "could not delete scan")
	}
	if !deleted.OK {
		gologger.Error().Msgf("Error in deleting the scan %s.", id)
	} else {
		gologger.Info().Msgf("Scan deleted %s.", id)
	}
	return nil
}

func (r *Runner) getResults(id string, limit int) error {
	ID, _ := strconv.ParseInt(id, 10, 64)
	err := r.cloudClient.GetResults(ID, false, limit, func(re *output.ResultEvent) {
		if outputErr := r.output.Write(re); outputErr != nil {
			gologger.Warning().Msgf("Could not write output: %s", outputErr)
		}
	})
	return err
}

func (r *Runner) getTarget(id string) error {
	var name string
	ID, parseErr := strconv.ParseInt(id, 10, 64)
	if parseErr != nil {
		name = id
	}

	reader, err := r.cloudClient.GetTarget(ID, name)
	if err != nil {
		return errors.Wrap(err, "could not get target")
	}
	defer reader.Close()

	_, _ = io.Copy(os.Stdout, reader)
	return nil
}

func (r *Runner) getTemplate(id string) error {
	var name string
	ID, parseErr := strconv.ParseInt(id, 10, 64)
	if parseErr != nil {
		name = id
	}

	reader, err := r.cloudClient.GetTemplate(ID, name)
	if err != nil {
		return errors.Wrap(err, "could not get template")
	}
	defer reader.Close()

	_, _ = io.Copy(os.Stdout, reader)
	return nil
}

func (r *Runner) removeDatasource(datasource string) error {
	var source string
	ID, parseErr := strconv.ParseInt(datasource, 10, 64)
	if parseErr != nil {
		source = datasource
	}

	err := r.cloudClient.RemoveDatasource(ID, source)
	if err == nil {
		gologger.Info().Msgf("Datasource deleted %s", datasource)
	}
	return err
}

func (r *Runner) addTemplate(location string) error {
	walkErr := filepath.WalkDir(location, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".yaml") {
			return nil
		}
		base := filepath.Base(path)
		reference, templateErr := r.cloudClient.AddTemplate(base, path)
		if templateErr != nil {
			gologger.Error().Msgf("Could not upload %s: %s", path, templateErr)
		} else if reference != "" {
			gologger.Info().Msgf("Uploaded template %s: %s", base, reference)
		}
		return nil
	})
	return walkErr
}

func (r *Runner) addTarget(location string) error {
	walkErr := filepath.WalkDir(location, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".txt") {
			return nil
		}
		base := filepath.Base(location)
		reference, targetErr := r.cloudClient.AddTarget(base, location)
		if targetErr != nil {
			gologger.Error().Msgf("Could not upload %s: %s", location, targetErr)
		} else if reference != "" {
			gologger.Info().Msgf("Uploaded target %s: %s", base, reference)
		}
		return nil
	})
	return walkErr
}

func (r *Runner) removeTarget(item string) error {
	var err error
	if ID, parseErr := strconv.ParseInt(item, 10, 64); parseErr == nil {
		err = r.cloudClient.RemoveTarget(ID, "")
	} else if strings.EqualFold(path.Ext(item), ".txt") {
		err = r.cloudClient.RemoveTarget(0, item)
	} else {
		return r.removeTargetPrefix(item)
	}
	if err != nil {
		gologger.Error().Msgf("Error in deleting target %s: %s", item, err)
	} else {
		gologger.Info().Msgf("Target deleted %s", item)
	}
	return nil
}

func (r *Runner) removeTargetPrefix(item string) error {
	response, err := r.cloudClient.ListTargets(item)
	if err != nil {
		return errors.Wrap(err, "could not list targets")
	}
	for _, item := range response {
		if err := r.cloudClient.RemoveTarget(item.ID, ""); err != nil {
			gologger.Error().Msgf("Error in deleting target %s: %s", item.Reference, err)
		} else {
			gologger.Info().Msgf("Target deleted %s", item.Reference)
		}
	}
	return nil
}

func (r *Runner) removeTemplate(item string) error {
	var err error
	if ID, parseErr := strconv.ParseInt(item, 10, 64); parseErr == nil {
		err = r.cloudClient.RemoveTemplate(ID, "")
	} else if strings.EqualFold(path.Ext(item), ".yaml") {
		err = r.cloudClient.RemoveTemplate(0, item)
	} else {
		return r.removeTemplatePrefix(item)
	}
	if err != nil {
		gologger.Error().Msgf("Error in deleting template %s: %s", item, err)
	} else {
		gologger.Info().Msgf("Template deleted %s", item)
	}
	return nil
}

func (r *Runner) removeTemplatePrefix(item string) error {
	response, err := r.cloudClient.ListTemplates(item)
	if err != nil {
		return errors.Wrap(err, "could not list templates")
	}
	for _, item := range response {
		if err := r.cloudClient.RemoveTemplate(item.ID, ""); err != nil {
			gologger.Error().Msgf("Error in deleting template %s: %s", item.Reference, err)
		} else {
			gologger.Info().Msgf("Template deleted %s", item.Reference)
		}
	}
	return nil
}

// initializeCloudDataSources initializes cloud data sources
func (r *Runner) addCloudDataSource(source string) error {
	switch source {
	case "s3":
		token := strings.Join([]string{r.options.AwsAccessKey, r.options.AwsSecretKey, r.options.AwsRegion}, ":")
		if _, err := r.processDataSourceItem(r.options.AwsBucketName, token, "s3"); err != nil {
			return err
		}
	case "github":
		for _, repo := range r.options.GithubTemplateRepo {
			if _, err := r.processDataSourceItem(repo, r.options.GithubToken, "github"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Runner) processDataSourceItem(repo, token, Type string) (int64, error) {
	ID, err := r.cloudClient.StatusDataSource(nucleicloud.StatusDataSourceRequest{Repo: repo, Token: token})
	if err != nil {
		if !strings.Contains(err.Error(), "no rows in result set") {
			return 0, errors.Wrap(err, "could not get data source status")
		}

		gologger.Info().Msgf("Adding new data source + syncing: %s\n", repo)
		resp, err := r.cloudClient.AddDataSource(nucleicloud.AddDataSourceRequest{Type: Type, Repo: repo, Token: token})
		if err != nil {
			return 0, errors.Wrap(err, "could not add data source")
		}
		ID = resp.ID
		if err = r.cloudClient.SyncDataSource(resp.ID); err != nil {
			return 0, errors.Wrap(err, "could not sync data source")
		}
		if resp.Secret != "" {
			gologger.Info().Msgf("Webhook URL for added source: %s/datasources/%s/webhook", r.options.CloudURL, resp.Hash)
			gologger.Info().Msgf("Secret for webhook: %s", resp.Secret)
		}
	}
	if r.options.UpdateTemplates {
		gologger.Info().Msgf("Syncing data source: %s (%d)\n", repo, ID)
		if err = r.cloudClient.SyncDataSource(ID); err != nil {
			return 0, errors.Wrap(err, "could not sync data source")
		}
	}
	return ID, nil
}
