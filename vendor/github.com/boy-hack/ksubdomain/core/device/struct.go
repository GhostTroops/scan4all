package device

import (
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"net"
)

type SelfMac net.HardwareAddr

func (d SelfMac) String() string {
	n := (net.HardwareAddr)(d)
	return n.String()
}
func (d SelfMac) MarshalYAML() (interface{}, error) {
	n := (net.HardwareAddr)(d)
	return n.String(), nil
}
func (d SelfMac) HardwareAddr() net.HardwareAddr {
	n := (net.HardwareAddr)(d)
	return n
}
func (d *SelfMac) UnmarshalYAML(value *yaml.Node) error {
	v := value.Value
	v2, err := net.ParseMAC(v)
	if err != nil {
		return err
	}
	n := SelfMac(v2)
	*d = n
	return nil
}

type EtherTable struct {
	SrcIp  net.IP  `yaml:"src_ip"`
	Device string  `yaml:"device"`
	SrcMac SelfMac `yaml:"src_mac"`
	DstMac SelfMac `yaml:"dst_mac"`
}

func ReadConfig(filename string) (*EtherTable, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var ether EtherTable
	err = yaml.Unmarshal(data, &ether)
	if err != nil {
		return nil, err
	}
	return &ether, nil
}
func (e *EtherTable) SaveConfig(filename string) error {
	data, err := yaml.Marshal(e)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, data, 0666)
}
