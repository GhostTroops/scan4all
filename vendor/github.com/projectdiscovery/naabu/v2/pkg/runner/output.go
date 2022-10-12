package runner

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// Result contains the result for a host
type Result struct {
	Host      string    `json:"host,omitempty" csv:"host"`
	IP        string    `json:"ip,omitempty" csv:"ip"`
	Port      int       `json:"port" csv:"port"`
	IsCDNIP   bool      `json:"cdn,omitempty" csv:"cdn"`
	CDNName   string    `json:"cdn-name,omitempty" csv:"cdn-name"`
	TimeStamp time.Time `json:"timestamp" csv:"timestamp"`
}

func (r *Result) JSON() ([]byte, error) {
	return json.Marshal(r)
}

var NumberOfCsvFieldsErr = errors.New("exported fields don't match csv tags")

func (r *Result) CSVHeaders() ([]string, error) {
	ty := reflect.TypeOf(*r)
	var headers []string
	for i := 0; i < ty.NumField(); i++ {
		headers = append(headers, ty.Field(i).Tag.Get("csv"))
	}
	if len(headers) != ty.NumField() {
		return nil, NumberOfCsvFieldsErr
	}
	return headers, nil
}

func (r *Result) CSVFields() ([]string, error) {
	var fields []string
	vl := reflect.ValueOf(*r)
	for i := 0; i < vl.NumField(); i++ {
		fields = append(fields, fmt.Sprint(vl.Field(i).Interface()))
	}
	if len(fields) != vl.NumField() {
		return nil, NumberOfCsvFieldsErr
	}
	return fields, nil
}

// WriteHostOutput writes the output list of host ports to an io.Writer
func WriteHostOutput(host string, ports []int, cdnName string, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for _, port := range ports {
		sb.WriteString(host)
		sb.WriteString(":")
		sb.WriteString(strconv.Itoa(port))
		if cdnName != "" {
			sb.WriteString(" [" + cdnName + "]")
		}
		sb.WriteString("\n")

		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}

// WriteJSONOutput writes the output list of subdomain in JSON to an io.Writer
func WriteJSONOutput(host, ip string, ports []int, isCdn bool, cdnName string, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	data := Result{TimeStamp: time.Now().UTC()}
	if host != ip {
		data.Host = host
	}
	data.IP = ip
	data.IsCDNIP = isCdn
	data.CDNName = cdnName
	for _, port := range ports {
		data.Port = port
		err := encoder.Encode(&data)
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteCsvOutput writes the output list of subdomain in csv format to an io.Writer
func WriteCsvOutput(host, ip string, ports []int, isCdn bool, cdnName string, header bool, writer io.Writer) error {
	encoder := csv.NewWriter(writer)
	data := &Result{TimeStamp: time.Now().UTC()}
	if header {
		writeCSVHeaders(data, encoder)
	}
	if host != ip {
		data.Host = host
	}
	data.IP = ip
	data.IsCDNIP = isCdn
	data.CDNName = cdnName
	for _, port := range ports {
		data.Port = port
		writeCSVRow(data, encoder)
	}
	encoder.Flush()
	return nil
}
