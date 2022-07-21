package shodan

type ShodanResponse struct {
	Total   int                      `json:"total"`
	Results []map[string]interface{} `json:"matches"`
}
