package asnmap

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"time"
)

// To model json & csv formatted output
type Result struct {
	Timestamp  string   `json:"timestamp,omitempty" csv:"timestamp"`
	Input      string   `json:"input" csv:"input"`
	ASN        string   `json:"as_number" csv:"as_number"`
	ASN_org    string   `json:"as_name" csv:"as_name"`
	AS_country string   `json:"as_country" csv:"as_country"`
	AS_range   []string `json:"as_range" csv:"as_range"`
}

// To model http response from server
type Response struct {
	FirstIp string
	LastIp  string
	Input   string
	ASN     int
	Country string
	Org     string
}

// attachPrefix func attaches 'AS' prefix to ASN numbers
func attachPrefix(input string) string {
	inp := input
	if _, err := strconv.Atoi(input); err == nil {
		inp = "AS" + input
	}
	return inp
}

func convertIPsToStringSlice(ips []*net.IPNet) []string {
	var res []string
	for _, ip := range ips {
		res = append(res, ip.String())
	}
	return res
}

func intializeResult(resp *Response) (*Result, error) {
	result := &Result{}
	result.Timestamp = time.Now().Local().String()
	result.Input = attachPrefix(resp.Input)
	result.ASN = attachPrefix(strconv.Itoa(resp.ASN))
	result.ASN_org = resp.Org
	result.AS_country = resp.Country
	cidrs, err := GetCIDR([]*Response{resp})
	if err != nil {
		return nil, err
	}
	result.AS_range = convertIPsToStringSlice(cidrs)
	return result, nil
}

func prepareFormattedJSON(input *Response) ([]byte, error) {
	result, err := intializeResult(input)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

func prepareFormattedCSV(input *Response) ([]string, error) {
	result, err := intializeResult(input)
	if err != nil {
		return nil, err
	}
	record := []string{result.Timestamp, result.Input, result.ASN, result.ASN_org, result.AS_country, strings.Join(result.AS_range, ",")}
	return record, nil
}

func GetFormattedDataInJson(output []*Response) ([]byte, error) {
	var jsonOutput []byte
	for _, res := range output {
		json, err := prepareFormattedJSON(res)
		if err != nil {
			return nil, err
		}
		jsonOutput = append(jsonOutput, json...)
	}
	return jsonOutput, nil
}

func GetFormattedDataInCSV(output []*Response) ([][]string, error) {
	records := [][]string{}
	for _, res := range output {
		record, err := prepareFormattedCSV(res)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	return records, nil
}
