package Configs

// json 模式的payload
type ExpJson struct {
	Name        string `json:"Name"`
	Description string `json:"Description"`
	Product     string `json:"Product"`
	Author      string `json:"author"`

	// 请求数据
	// 可以看出，这种简单的定义，还是不如nuclei，多个请求之间的关系无法分号表达
	Request []struct {
		Method           string            `json:"Method"`
		Header           map[string]string `json:"Header"`
		Uri              string            `json:"Uri"`
		Port             string            `json:"Port"`
		Data             string            `json:"Data"`
		Follow_redirects string            `json:"Follow_redirects"`
		// 文件上传
		Upload struct {
			Name     string `json:"Name"`
			FileName string `json:"fileName"`
			FilePath string `json:"FilePath"`
		} `json:"Upload"`
		// 响应
		Response struct {
			Check_Steps string `json:"Check_Steps"`
			Checks      []struct {
				Operation string `json:"Operation"`
				Key       string `json:"Key"`
				Value     string `json:"Value"`
			} `json:"Checks"`
		}
		Search      string `json:"Search"`
		Next_decide string `json:"Next_decide"`
	} `json:"Request"`
}

type ConfigJson struct {
	Exploit struct {
		Path string `json:"Path"`
	} `json:"Exploit"`
}

type UserOption struct {
	OriAddr   string // 原始地址
	UriAddr   string // 拼接Uri参数后的变化地址
	JsonFile  string // 设定的json文档
	AllJson   bool   //使用全部的json文件，也就是全部漏洞去跑
	KeyWord   string // 查找的关键字
	File      string //设定从文件中读取url
	ThreadNum int    //定义线程数量
	GetTitle  bool   //获取url标题专用

}

type HttpResult struct {
	Resp *[]byte
	Body string
}

type FileNameStruct struct { //用来接收文件名等参数
	Name     string
	Filename string
	FilePath string
}
