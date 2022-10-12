package quake

type Request struct {
	Query       string   `json:"query"`
	Size        int      `json:"size"`
	Start       int      `json:"start"`
	IgnoreCache bool     `json:"ignore_cache"`
	Include     []string `json:"include"`
}
