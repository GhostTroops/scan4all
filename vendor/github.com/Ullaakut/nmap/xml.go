package nmap

import (
	"bytes"
	"encoding/xml"
	"io"
	"io/ioutil"
	"strconv"
	"time"

	family "github.com/Ullaakut/nmap/pkg/osfamilies"
)

// Run represents an nmap scanning run.
type Run struct {
	XMLName xml.Name `xml:"nmaprun"`

	Args             string         `xml:"args,attr" json:"args"`
	ProfileName      string         `xml:"profile_name,attr" json:"profile_name"`
	Scanner          string         `xml:"scanner,attr" json:"scanner"`
	StartStr         string         `xml:"startstr,attr" json:"start_str"`
	Version          string         `xml:"version,attr" json:"version"`
	XMLOutputVersion string         `xml:"xmloutputversion,attr" json:"xml_output_version"`
	Debugging        Debugging      `xml:"debugging" json:"debugging"`
	Stats            Stats          `xml:"runstats" json:"run_stats"`
	ScanInfo         ScanInfo       `xml:"scaninfo" json:"scan_info"`
	Start            Timestamp      `xml:"start,attr" json:"start"`
	Verbose          Verbose        `xml:"verbose" json:"verbose"`
	Hosts            []Host         `xml:"host" json:"hosts"`
	PostScripts      []Script       `xml:"postscript>script" json:"post_scripts"`
	PreScripts       []Script       `xml:"prescript>script" json:"pre_scripts"`
	Targets          []Target       `xml:"target" json:"targets"`
	TaskBegin        []Task         `xml:"taskbegin" json:"task_begin"`
	TaskProgress     []TaskProgress `xml:"taskprogress" json:"task_progress"`
	TaskEnd          []Task         `xml:"taskend" json:"task_end"`

	NmapErrors []string
	rawXML     []byte
}

// ToFile writes a Run as XML into the specified file path.
func (r Run) ToFile(filePath string) error {
	return ioutil.WriteFile(filePath, r.rawXML, 0666)
}

// ToReader writes the raw XML into an streamable buffer.
func (r Run) ToReader() io.Reader {
	return bytes.NewReader(r.rawXML)
}

// ScanInfo represents the scan information.
type ScanInfo struct {
	NumServices int    `xml:"numservices,attr" json:"num_services"`
	Protocol    string `xml:"protocol,attr" json:"protocol"`
	ScanFlags   string `xml:"scanflags,attr" json:"scan_flags"`
	Services    string `xml:"services,attr" json:"services"`
	Type        string `xml:"type,attr" json:"type"`
}

// Verbose contains the verbosity level of the scan.
type Verbose struct {
	Level int `xml:"level,attr" json:"level"`
}

// Debugging contains the debugging level of the scan.
type Debugging struct {
	Level int `xml:"level,attr" json:"level"`
}

// Task contains information about a task.
type Task struct {
	Time      Timestamp `xml:"time,attr" json:"time"`
	Task      string    `xml:"task,attr" json:"task"`
	ExtraInfo string    `xml:"extrainfo,attr" json:"extra_info"`
}

// TaskProgress contains information about the progression of a task.
type TaskProgress struct {
	Percent   float32   `xml:"percent,attr" json:"percent"`
	Remaining int       `xml:"remaining,attr" json:"remaining"`
	Task      string    `xml:"task,attr" json:"task"`
	Etc       Timestamp `xml:"etc,attr" json:"etc"`
	Time      Timestamp `xml:"time,attr" json:"time"`
}

// Target represents a target, how it was specified when passed to nmap,
// its status and the reason for its status. Example:
// <target specification="domain.does.not.exist" status="skipped" reason="invalid"/>
type Target struct {
	Specification string `xml:"specification,attr" json:"specification"`
	Status        string `xml:"status,attr" json:"status"`
	Reason        string `xml:"reason,attr" json:"reason"`
}

// Host represents a host that was scanned.
type Host struct {
	Distance      Distance      `xml:"distance" json:"distance"`
	EndTime       Timestamp     `xml:"endtime,attr,omitempty" json:"end_time"`
	IPIDSequence  IPIDSequence  `xml:"ipidsequence" json:"ip_id_sequence"`
	OS            OS            `xml:"os" json:"os"`
	StartTime     Timestamp     `xml:"starttime,attr,omitempty" json:"start_time"`
	Status        Status        `xml:"status" json:"status"`
	TCPSequence   TCPSequence   `xml:"tcpsequence" json:"tcp_sequence"`
	TCPTSSequence TCPTSSequence `xml:"tcptssequence" json:"tcp_ts_sequence"`
	Times         Times         `xml:"times" json:"times"`
	Trace         Trace         `xml:"trace" json:"trace"`
	Uptime        Uptime        `xml:"uptime" json:"uptime"`
	Comment       string        `xml:"comment,attr" json:"comment"`
	Addresses     []Address     `xml:"address" json:"addresses"`
	ExtraPorts    []ExtraPort   `xml:"ports>extraports" json:"extra_ports"`
	Hostnames     []Hostname    `xml:"hostnames>hostname" json:"hostnames"`
	HostScripts   []Script      `xml:"hostscript>script" json:"host_scripts"`
	Ports         []Port        `xml:"ports>port" json:"ports"`
	Smurfs        []Smurf       `xml:"smurf" json:"smurfs"`
}

// Status represents a host's status.
type Status struct {
	State     string  `xml:"state,attr" json:"state"`
	Reason    string  `xml:"reason,attr" json:"reason"`
	ReasonTTL float32 `xml:"reason_ttl,attr" json:"reason_ttl"`
}

func (s Status) String() string {
	return s.State
}

// Address contains a IPv4 or IPv6 address for a host.
type Address struct {
	Addr     string `xml:"addr,attr" json:"addr"`
	AddrType string `xml:"addrtype,attr" json:"addr_type"`
	Vendor   string `xml:"vendor,attr" json:"vendor"`
}

func (a Address) String() string {
	return a.Addr
}

// Hostname is a name for a host.
type Hostname struct {
	Name string `xml:"name,attr" json:"name"`
	Type string `xml:"type,attr" json:"type"`
}

func (h Hostname) String() string {
	return h.Name
}

// Smurf contains responses from a smurf attack.
type Smurf struct {
	Responses string `xml:"responses,attr" json:"responses"`
}

// ExtraPort contains the information about the closed and filtered ports.
type ExtraPort struct {
	State   string   `xml:"state,attr" json:"state"`
	Count   int      `xml:"count,attr" json:"count"`
	Reasons []Reason `xml:"extrareasons" json:"reasons"`
}

// Reason represents a reason why a port is closed or filtered.
// This won't be in the scan results unless WithReason is used.
type Reason struct {
	Reason string `xml:"reason,attr" json:"reason"`
	Count  int    `xml:"count,attr" json:"count"`
}

// Port contains all the information about a scanned port.
type Port struct {
	ID       uint16   `xml:"portid,attr" json:"id"`
	Protocol string   `xml:"protocol,attr" json:"protocol"`
	Owner    Owner    `xml:"owner" json:"owner"`
	Service  Service  `xml:"service" json:"service"`
	State    State    `xml:"state" json:"state"`
	Scripts  []Script `xml:"script" json:"scripts"`
}

// PortStatus represents a port's state.
type PortStatus string

// Enumerates the different possible state values.
const (
	Open       PortStatus = "open"
	Closed     PortStatus = "closed"
	Filtered   PortStatus = "filtered"
	Unfiltered PortStatus = "unfiltered"
)

// Status returns the status of a port.
func (p Port) Status() PortStatus {
	return PortStatus(p.State.State)
}

// State contains information about a given port's status.
// State will be open, closed, etc.
type State struct {
	State     string  `xml:"state,attr" json:"state"`
	Reason    string  `xml:"reason,attr" json:"reason"`
	ReasonIP  string  `xml:"reason_ip,attr" json:"reason_ip"`
	ReasonTTL float32 `xml:"reason_ttl,attr" json:"reason_ttl"`
}

func (s State) String() string {
	return s.State
}

// Owner contains the name of a port's owner.
type Owner struct {
	Name string `xml:"name,attr" json:"name"`
}

func (o Owner) String() string {
	return o.Name
}

// Service contains detailed information about a service on an open port.
type Service struct {
	DeviceType    string `xml:"devicetype,attr" json:"device_type"`
	ExtraInfo     string `xml:"extrainfo,attr" json:"extra_info"`
	HighVersion   string `xml:"highver,attr" json:"high_version"`
	Hostname      string `xml:"hostname,attr" json:"hostname"`
	LowVersion    string `xml:"lowver,attr" json:"low_version"`
	Method        string `xml:"method,attr" json:"method"`
	Name          string `xml:"name,attr" json:"name"`
	OSType        string `xml:"ostype,attr" json:"os_type"`
	Product       string `xml:"product,attr" json:"product"`
	Proto         string `xml:"proto,attr" json:"proto"`
	RPCNum        string `xml:"rpcnum,attr" json:"rpc_num"`
	ServiceFP     string `xml:"servicefp,attr" json:"service_fp"`
	Tunnel        string `xml:"tunnel,attr" json:"tunnel"`
	Version       string `xml:"version,attr" json:"version"`
	Configuration int    `xml:"conf,attr" json:"configuration"`
	CPEs          []CPE  `xml:"cpe" json:"cpes"`
}

func (s Service) String() string {
	return s.Name
}

// CPE (Common Platform Enumeration) is a standardized way to name software
// applications, operating systems and hardware platforms.
type CPE string

// Script represents an Nmap Scripting Engine script.
// The inner elements can be an arbitrary collection of Tables and Elements. Both of them can also be empty.
type Script struct {
	ID       string    `xml:"id,attr" json:"id"`
	Output   string    `xml:"output,attr" json:"output"`
	Elements []Element `xml:"elem,omitempty" json:"elements,omitempty"`
	Tables   []Table   `xml:"table,omitempty" json:"tables,omitempty"`
}

// Table is an arbitrary collection of (sub-)Tables and Elements. All its fields can be empty.
type Table struct {
	Key      string    `xml:"key,attr,omitempty" json:"key,omitempty"`
	Tables   []Table   `xml:"table,omitempty" json:"tables,omitempty"`
	Elements []Element `xml:"elem,omitempty" json:"elements,omitempty"`
}

// Element is the smallest building block for scripts/tables. It can optionally(!) have a key.
type Element struct {
	Key   string `xml:"key,attr,omitempty" json:"key,omitempty"`
	Value string `xml:",innerxml" json:"value"`
}

// OS contains the fingerprinted operating system for a host.
type OS struct {
	PortsUsed    []PortUsed      `xml:"portused" json:"ports_used"`
	Matches      []OSMatch       `xml:"osmatch" json:"os_matches"`
	Fingerprints []OSFingerprint `xml:"osfingerprint" json:"os_fingerprints"`
}

// PortUsed is the port used to fingerprint an operating system.
type PortUsed struct {
	State string `xml:"state,attr" json:"state"`
	Proto string `xml:"proto,attr" json:"proto"`
	ID    int    `xml:"portid,attr" json:"port_id"`
}

// OSMatch contains detailed information regarding an operating system fingerprint.
type OSMatch struct {
	Name     string    `xml:"name,attr" json:"name"`
	Accuracy int       `xml:"accuracy,attr" json:"accuracy"`
	Line     int       `xml:"line,attr" json:"line"`
	Classes  []OSClass `xml:"osclass" json:"os_classes"`
}

// OSClass contains vendor information about an operating system.
type OSClass struct {
	Vendor       string `xml:"vendor,attr" json:"vendor"`
	OSGeneration string `xml:"osgen,attr" json:"os_generation"`
	Type         string `xml:"type,attr" json:"type"`
	Accuracy     int    `xml:"accuracy,attr" json:"accuracy"`
	Family       string `xml:"osfamily,attr" json:"os_family"`
	CPEs         []CPE  `xml:"cpe" json:"cpes"`
}

// OSFamily returns the OS family in an enumerated format.
func (o OSClass) OSFamily() family.OSFamily {
	return family.OSFamily(o.Family)
}

// OSFingerprint is the actual fingerprint string of an operating system.
type OSFingerprint struct {
	Fingerprint string `xml:"fingerprint,attr" json:"fingerprint"`
}

// Distance is the amount of hops to a particular host.
type Distance struct {
	Value int `xml:"value,attr" json:"value"`
}

// Uptime is the amount of time the host has been up.
type Uptime struct {
	Seconds  int    `xml:"seconds,attr" json:"seconds"`
	Lastboot string `xml:"lastboot,attr" json:"last_boot"`
}

// Sequence represents a detected sequence.
type Sequence struct {
	Class  string `xml:"class,attr" json:"class"`
	Values string `xml:"values,attr" json:"values"`
}

// TCPSequence represents a detected TCP sequence.
type TCPSequence struct {
	Index      int    `xml:"index,attr" json:"index"`
	Difficulty string `xml:"difficulty,attr" json:"difficulty"`
	Values     string `xml:"values,attr" json:"values"`
}

// IPIDSequence represents a detected IP ID sequence.
type IPIDSequence Sequence

// TCPTSSequence represents a detected TCP TS sequence.
type TCPTSSequence Sequence

// Trace represents the trace to a host, including the hops.
type Trace struct {
	Proto string `xml:"proto,attr" json:"proto"`
	Port  int    `xml:"port,attr" json:"port"`
	Hops  []Hop  `xml:"hop" json:"hops"`
}

// Hop is an IP hop to a host.
type Hop struct {
	TTL    float32 `xml:"ttl,attr" json:"ttl"`
	RTT    string  `xml:"rtt,attr" json:"rtt"`
	IPAddr string  `xml:"ipaddr,attr" json:"ip_addr"`
	Host   string  `xml:"host,attr" json:"host"`
}

// Times contains time statistics for an nmap scan.
type Times struct {
	SRTT string `xml:"srtt,attr" json:"srtt"`
	RTT  string `xml:"rttvar,attr" json:"rttv"`
	To   string `xml:"to,attr" json:"to"`
}

// Stats contains statistics for an nmap scan.
type Stats struct {
	Finished Finished  `xml:"finished" json:"finished"`
	Hosts    HostStats `xml:"hosts" json:"hosts"`
}

// Finished contains detailed statistics regarding a finished scan.
type Finished struct {
	Time     Timestamp `xml:"time,attr" json:"time"`
	TimeStr  string    `xml:"timestr,attr" json:"time_str"`
	Elapsed  float32   `xml:"elapsed,attr" json:"elapsed"`
	Summary  string    `xml:"summary,attr" json:"summary"`
	Exit     string    `xml:"exit,attr" json:"exit"`
	ErrorMsg string    `xml:"errormsg,attr" json:"error_msg"`
}

// HostStats contains the amount of up and down hosts and the total count.
type HostStats struct {
	Up    int `xml:"up,attr" json:"up"`
	Down  int `xml:"down,attr" json:"down"`
	Total int `xml:"total,attr" json:"total"`
}

// Timestamp represents time as a UNIX timestamp in seconds.
type Timestamp time.Time

// ParseTime converts a UNIX timestamp string to a time.Time.
func (t *Timestamp) ParseTime(s string) error {
	timestamp, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}

	*t = Timestamp(time.Unix(timestamp, 0))

	return nil
}

// FormatTime formats the time.Time value as a UNIX timestamp string.
func (t Timestamp) FormatTime() string {
	return strconv.FormatInt(time.Time(t).Unix(), 10)
}

// MarshalJSON implements the json.Marshaler interface.
func (t Timestamp) MarshalJSON() ([]byte, error) {
	return []byte(t.FormatTime()), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (t *Timestamp) UnmarshalJSON(b []byte) error {
	return t.ParseTime(string(b))
}

// MarshalXMLAttr implements the xml.MarshalerAttr interface.
func (t Timestamp) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	if time.Time(t).IsZero() {
		return xml.Attr{}, nil
	}

	return xml.Attr{Name: name, Value: t.FormatTime()}, nil
}

// UnmarshalXMLAttr implements the xml.UnmarshalXMLAttr interface.
func (t *Timestamp) UnmarshalXMLAttr(attr xml.Attr) (err error) {
	return t.ParseTime(attr.Value)
}

// Parse takes a byte array of nmap xml data and unmarshals it into a
// Run struct.
func Parse(content []byte) (*Run, error) {
	r := &Run{
		rawXML: content,
	}

	err := xml.Unmarshal(content, r)

	return r, err
}
