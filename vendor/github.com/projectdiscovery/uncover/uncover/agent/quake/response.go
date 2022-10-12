package quake

type responseData struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
}

type pagination struct {
	Count     int   `json:"count"`
	PageIndex int   `json:"page_index"`
	PageSize  int   `json:"page_size"`
	Total     int64 `json:"total"`
}

type meta struct {
	Pagination pagination `json:"pagination"`
}

type Response struct {
	Code    int            `json:"code"`
	Data    []responseData `json:"data"`
	Message string         `json:"message"`
	Meta    meta           `json:"meta"`
}
