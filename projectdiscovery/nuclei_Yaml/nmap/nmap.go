package nmap

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/lair-framework/go-nmap"
	"os/exec"
	"strconv"
)

type Nmap struct {
	SystemPath  string
	Args        []string
	Ports       string
	Exclude     string
	HostTimeOut string
	IP          string
	Result      []byte
}

type NmapResult struct {
	Ip        string
	StartTime string
	EndTime   string
	PortId    int
	Protocol  string
	Service   string
	Product   string
	Version   string
}

type Ports struct {
	Protocol string
	PortId   int
	State    string
	Service  string
	Product  string
	Reason   string
	Version  string
}

type Os struct {
	Name     string
	Accuracy int
}

func New() *Nmap {
	return &Nmap{}
}

func (n *Nmap) SetSystemPath(systemPath string) {
	if systemPath != "" {
		n.SystemPath = systemPath
	}
}

func (n *Nmap) SetArgs(arg ...string) {
	n.Args = arg
}

func (n *Nmap) SetIpPorts(ip string, ports string) {
	n.IP = ip
	n.Ports = ports
}

func (n *Nmap) SetHostTimeOut(hostTimeOut string) {
	n.HostTimeOut = hostTimeOut
}

func (n *Nmap) AppendSingleParma(parma string) {
	n.Args = append(n.Args, parma)
	n.Args = append(n.Args, "")
}

func (n *Nmap) Run() error {
	var cmd *exec.Cmd
	var outb, errs bytes.Buffer

	if n.IP != "" {
		n.Args = append(n.Args, n.IP)
	}

	if n.Ports != "" {
		n.Args = append(n.Args, "-p")
		n.Args = append(n.Args, n.Ports)
	}

	if n.HostTimeOut != "" {
		n.Args = append(n.Args, "--host-timeout")
		n.Args = append(n.Args, n.HostTimeOut)
	}

	if n.Exclude != "" {
		n.Args = append(n.Args, "--exclude")
		n.Args = append(n.Args, n.Exclude)
	}
	cmd = exec.Command(n.SystemPath, n.Args...)
	fmt.Println(cmd.Args)
	cmd.Stdout = &outb
	cmd.Stderr = &errs
	err := cmd.Run()
	if err != nil {
		if errs.Len() > 0 {
			return errors.New(errs.String())
		}
		return err
	}
	n.Result = outb.Bytes()
	return nil
}

func (n *Nmap) Parse() ([]NmapResult, error) {
	var nmapResults []NmapResult
	n1, err := nmap.Parse(n.Result)
	if err != nil {
		fmt.Println("nmap parse error:", err.Error())
		return nil, err
	}
	for i := 0; i < len(n1.Hosts); i++ {
		if n1.Hosts[i].Status.State == "up" {
			var (
				nPort    Ports
				PortList []Ports
				Os       Os
			)
			IP := n1.Hosts[i].Addresses[0].Addr
			StartTime, _ := n1.Hosts[i].StartTime.MarshalJSON()
			EndTime, _ := n1.Hosts[i].EndTime.MarshalJSON()
			for t := 0; t < len(n1.Hosts[i].Ports); t++ {
				nPort.PortId = n1.Hosts[i].Ports[t].PortId
				nPort.Protocol = n1.Hosts[i].Ports[t].Protocol
				nPort.Service = n1.Hosts[i].Ports[t].Service.Name
				nPort.Product = n1.Hosts[i].Ports[t].Service.Product
				nPort.Version = n1.Hosts[i].Ports[t].Service.Version
				nPort.Reason = n1.Hosts[i].Ports[t].State.Reason
				PortList = append(PortList, nPort)
			}
			for y := 0; y < len(n1.Hosts[i].Os.OsMatches); y++ {
				tmp, _ := strconv.Atoi(n1.Hosts[i].Os.OsMatches[y].Accuracy)
				if tmp > Os.Accuracy {
					Os.Name = n1.Hosts[i].Os.OsMatches[y].Name
					Os.Accuracy = tmp
				}
			}
			if len(PortList) != 0 {
				for _, v := range PortList {
					nmapResults = append(nmapResults, NmapResult{
						Ip:        IP,
						StartTime: string(StartTime) + "000",
						EndTime:   string(EndTime) + "000",
						Service:   v.Service,
						PortId:    v.PortId,
						Protocol:  v.Protocol,
						Product:   v.Product,
						Version:   v.Version,
					})
				}
			}
		}
	}
	return nmapResults, err
}
