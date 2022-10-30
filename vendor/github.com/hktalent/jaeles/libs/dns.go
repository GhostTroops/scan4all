package libs

// Dns result for DNS
type Dns struct {
	Results  []DnsResult
	Resolver string
	Domain   string

	// for DNS part
	RecordType string `yaml:"record"` // ANY, A, CNAME

	Conditions  []string
	Middlewares []string
	Conclusions []string
	Detections  []string

	// run when detection is true
	PostRun []string
}

type DnsResult struct {
	RecordType string
	Data       string
}
