package PipelineHttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/textproto"
)

// post 发送的多文件
type PostFileData struct {
	ContentType string    `json:"content_type"`
	Name        string    `json:"name"`
	FileName    string    `json:"file_name"`
	FileData    io.Reader `json:"file_data"`
}

// 增加、支持：多文件上传
func (r *PipelineHttp) SendFiles(c *http.Client, szUrl string, parms *map[string]interface{}, files *[]PostFileData, fnCbk func(resp *http.Response, err error, szU string), setHeader func() map[string]string) {
	body_buf := bytes.NewBufferString("")
	// reader, writer := io.Pipe()// 这里不适合这样的场景，无法提前预知发送数据的总长度
	// head start
	body_writer := multipart.NewWriter(body_buf)
	// head end
	var err error
	var f01 io.Writer
	if nil != parms {
		var data []byte
		for k, v := range *parms {
			if f01, err = body_writer.CreateFormField(k); nil == err {
				if data, err = json.Marshal(v); nil == err {
					f01.Write(data)
					continue
				}
			}
			if nil != err {
				log.Println(err)
			}
		}
	}
	if nil != files {
		for _, x := range *files {
			mh := textproto.MIMEHeader{} // make(textproto.MIMEHeader)
			szC := x.ContentType
			if "" == szC {
				szC = "text/plain; charset=UTF-8"
			}
			mh.Set("Content-Type", szC)
			mh.Set("Content-Disposition", fmt.Sprintf("form-data; name=\"%s\"; filename=\"%s\"", x.Name, x.FileName))
			f01, err = body_writer.CreatePart(mh)
			if nil == err {
				io.Copy(f01, x.FileData)
				continue
			}
			if nil != err {
				log.Println(err)
			}
		}
	}
	body_writer.Close()
	bbData := body_buf.Bytes()
	r.DoGetWithClient4SetHd(c, szUrl, "POST", bytes.NewReader(bbData), fnCbk, func() map[string]string {
		m10 := setHeader()
		if nil == m10 {
			m10 = make(map[string]string)
		}
		m10["Content-Type"] = fmt.Sprintf("multipart/related; boundary=%s", body_writer.Boundary())
		m10["Content-Length"] = fmt.Sprintf("%d", len(bbData))
		//m10["Authorization"] = fmt.Sprintf("Bearer %s", accessToken)
		return m10
	}, true)
}
