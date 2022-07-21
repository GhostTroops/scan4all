package censys

type CensysResponse struct {
	Code    int                  `json:"code"`
	Status  string               `json:"status"`
	Results CensysResponseResult `json:"result"`
}

type CensysResponseResult struct {
	Query string                   `json:"query"`
	Total int                      `json:"total"`
	Hits  []map[string]interface{} `json:"hits"`
	Links CensysResponseLinks      `json:"links"`
}

type CensysResponseLinks struct {
	Prev string `json:"prev"`
	Next string `json:"next"`
}
