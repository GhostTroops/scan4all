package jira

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/andygrunwald/go-jira"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Integration is a client for an issue tracker integration
type Integration struct {
	jira    *jira.Client
	options *Options
}

// Options contains the configuration options for jira client
type Options struct {
	// Cloud value (optional) is set to true when Jira cloud is used
	Cloud bool `yaml:"cloud"`
	// UpdateExisting value (optional) if true, the existing opened issue is updated
	UpdateExisting bool `yaml:"update-existing"`
	// URL is the URL of the jira server
	URL string `yaml:"url" validate:"required"`
	// AccountID is the accountID of the jira user.
	AccountID string `yaml:"account-id" validate:"required"`
	// Email is the email of the user for jira instance
	Email string `yaml:"email" validate:"required,email"`
	// Token is the token for jira instance.
	Token string `yaml:"token" validate:"required"`
	// ProjectName is the name of the project.
	ProjectName string `yaml:"project-name" validate:"required"`
	// IssueType (optional) is the name of the created issue type
	IssueType string `yaml:"issue-type"`
	// SeverityAsLabel (optional) sends the severity as the label of the created
	// issue.
	SeverityAsLabel bool `yaml:"severity-as-label"`
	HttpClient      *retryablehttp.Client
}


// New creates a new issue tracker integration client based on options.
func New(options *Options) (*Integration, error) {
	username := options.Email
	if !options.Cloud {
		username = options.AccountID
	}
	tp := jira.BasicAuthTransport{
		Username: username,
		Password: options.Token,
	}
	if options.HttpClient != nil {
		tp.Transport = options.HttpClient.HTTPClient.Transport
	}
	jiraClient, err := jira.NewClient(tp.Client(), options.URL)
	if err != nil {
		return nil, err
	}
	return &Integration{jira: jiraClient, options: options}, nil
}

// CreateNewIssue creates a new issue in the tracker
func (i *Integration) CreateNewIssue(event *output.ResultEvent) error {
	summary := format.Summary(event)
	labels := []string{}
	severityLabel := fmt.Sprintf("Severity:%s", event.Info.SeverityHolder.Severity.String())
	if i.options.SeverityAsLabel && severityLabel != "" {
		labels = append(labels, severityLabel)
	}
	if label := i.options.IssueType; label != "" {
		labels = append(labels, label)
	}

	fields := &jira.IssueFields{
		Assignee:    &jira.User{AccountID: i.options.AccountID},
		Reporter:    &jira.User{AccountID: i.options.AccountID},
		Description: jiraFormatDescription(event),
		Type:        jira.IssueType{Name: i.options.IssueType},
		Project:     jira.Project{Key: i.options.ProjectName},
		Summary:     summary,
		Labels:      labels,
	}
	// On-prem version of Jira server does not use AccountID
	if !i.options.Cloud {
		fields = &jira.IssueFields{
			Assignee:    &jira.User{Name: i.options.AccountID},
			Description: jiraFormatDescription(event),
			Type:        jira.IssueType{Name: i.options.IssueType},
			Project:     jira.Project{Key: i.options.ProjectName},
			Summary:     summary,
			Labels:      labels,
		}
	}

	issueData := &jira.Issue{
		Fields: fields,
	}
	_, resp, err := i.jira.Issue.Create(issueData)
	if err != nil {
		var data string
		if resp != nil && resp.Body != nil {
			d, _ := io.ReadAll(resp.Body)
			data = string(d)
		}
		return fmt.Errorf("%w => %s", err, data)
	}
	return nil
}

// CreateIssue creates an issue in the tracker or updates the existing one
func (i *Integration) CreateIssue(event *output.ResultEvent) error {
	if i.options.UpdateExisting {
		issueID, err := i.FindExistingIssue(event)
		if err != nil {
			return err
		} else if issueID != "" {
			_, _, err = i.jira.Issue.AddComment(issueID, &jira.Comment{
				Body: jiraFormatDescription(event),
			})
			return err
		}
	}
	return i.CreateNewIssue(event)
}

// FindExistingIssue checks if the issue already exists and returns its ID
func (i *Integration) FindExistingIssue(event *output.ResultEvent) (string, error) {
	template := format.GetMatchedTemplate(event)
	jql := fmt.Sprintf("summary ~ \"%s\" AND summary ~ \"%s\" AND status = \"Open\"", template, event.Host)

	searchOptions := &jira.SearchOptions{
		MaxResults: 1, // if any issue exists, then we won't create a new one
	}

	chunk, resp, err := i.jira.Issue.Search(jql, searchOptions)
	if err != nil {
		var data string
		if resp != nil && resp.Body != nil {
			d, _ := io.ReadAll(resp.Body)
			data = string(d)
		}
		return "", fmt.Errorf("%w => %s", err, data)
	}

	switch resp.Total {
	case 0:
		return "", nil
	case 1:
		return chunk[0].ID, nil
	default:
		gologger.Warning().Msgf("Discovered multiple opened issues %s for the host %s: The issue [%s] will be updated.", template, event.Host, chunk[0].ID)
		return chunk[0].ID, nil
	}
}

// jiraFormatDescription formats a short description of the generated
// event by the nuclei scanner in Jira format.
func jiraFormatDescription(event *output.ResultEvent) string { // TODO remove the code duplication: format.go <-> jira.go
	template := format.GetMatchedTemplate(event)

	builder := &bytes.Buffer{}
	builder.WriteString("*Details*: *")
	builder.WriteString(template)
	builder.WriteString("* ")

	builder.WriteString(" matched at ")
	builder.WriteString(event.Host)

	builder.WriteString("\n\n*Protocol*: ")
	builder.WriteString(strings.ToUpper(event.Type))

	builder.WriteString("\n\n*Full URL*: ")
	builder.WriteString(event.Matched)

	builder.WriteString("\n\n*Timestamp*: ")
	builder.WriteString(event.Timestamp.Format("Mon Jan 2 15:04:05 -0700 MST 2006"))

	builder.WriteString("\n\n*Template Information*\n\n| Key | Value |\n")
	builder.WriteString(format.ToMarkdownTableString(&event.Info))

	builder.WriteString(createMarkdownCodeBlock("Request", event.Request))

	builder.WriteString("\n*Response*\n\n{code}\n")
	// If the response is larger than 5 kb, truncate it before writing.
	if len(event.Response) > 5*1024 {
		builder.WriteString(event.Response[:5*1024])
		builder.WriteString(".... Truncated ....")
	} else {
		builder.WriteString(event.Response)
	}
	builder.WriteString("\n{code}\n\n")

	if len(event.ExtractedResults) > 0 || len(event.Metadata) > 0 {
		builder.WriteString("\n*Extra Information*\n\n")
		if len(event.ExtractedResults) > 0 {
			builder.WriteString("*Extracted results*:\n\n")
			for _, v := range event.ExtractedResults {
				builder.WriteString("- ")
				builder.WriteString(v)
				builder.WriteString("\n")
			}
			builder.WriteString("\n")
		}
		if len(event.Metadata) > 0 {
			builder.WriteString("*Metadata*:\n\n")
			for k, v := range event.Metadata {
				builder.WriteString("- ")
				builder.WriteString(k)
				builder.WriteString(": ")
				builder.WriteString(types.ToString(v))
				builder.WriteString("\n")
			}
			builder.WriteString("\n")
		}
	}
	if event.Interaction != nil {
		builder.WriteString("*Interaction Data*\n---\n")
		builder.WriteString(event.Interaction.Protocol)
		if event.Interaction.QType != "" {
			builder.WriteString(" (")
			builder.WriteString(event.Interaction.QType)
			builder.WriteString(")")
		}
		builder.WriteString(" Interaction from ")
		builder.WriteString(event.Interaction.RemoteAddress)
		builder.WriteString(" at ")
		builder.WriteString(event.Interaction.UniqueID)

		if event.Interaction.RawRequest != "" {
			builder.WriteString(createMarkdownCodeBlock("Interaction Request", event.Interaction.RawRequest))
		}
		if event.Interaction.RawResponse != "" {
			builder.WriteString(createMarkdownCodeBlock("Interaction Response", event.Interaction.RawResponse))
		}
	}

	reference := event.Info.Reference
	if !reference.IsEmpty() {
		builder.WriteString("\nReferences: \n")

		referenceSlice := reference.ToSlice()
		for i, item := range referenceSlice {
			builder.WriteString("- ")
			builder.WriteString(item)
			if len(referenceSlice)-1 != i {
				builder.WriteString("\n")
			}
		}
	}
	builder.WriteString("\n")

	if event.CURLCommand != "" {
		builder.WriteString("\n*CURL Command*\n{code}\n")
		builder.WriteString(event.CURLCommand)
		builder.WriteString("\n{code}")
	}
	builder.WriteString(fmt.Sprintf("\n---\nGenerated by [Nuclei v%s](https://github.com/projectdiscovery/nuclei)", config.Version))
	data := builder.String()
	return data
}

func createMarkdownCodeBlock(title string, content string) string {
	return "\n" + createBoldMarkdown(title) + "\n" + content + "*\n\n{code}"
}

func createBoldMarkdown(value string) string {
	return "*" + value + "*\n\n{code}"
}
