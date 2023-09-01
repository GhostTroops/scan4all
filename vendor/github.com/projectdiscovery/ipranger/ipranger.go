package ipranger

import (
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/networkpolicy"
	iputil "github.com/projectdiscovery/utils/ip"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/yl2chen/cidranger"
)

type IPRanger struct {
	sync.RWMutex

	Np            *networkpolicy.NetworkPolicy
	iprangerop    cidranger.Ranger
	Hosts         *hybrid.HybridMap
	Stats         Stats
	CoalescedIPV4 []*net.IPNet
	CoalescedIPV6 []*net.IPNet
}

func New() (*IPRanger, error) {
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, err
	}
	var np networkpolicy.NetworkPolicy

	return &IPRanger{Np: &np, iprangerop: cidranger.NewPCTrieRanger(), Hosts: hm}, nil
}

func (ir *IPRanger) ContainsAll(hosts ...string) bool {
	for _, host := range hosts {
		if !ir.Contains(host) {
			return false
		}
	}
	return true
}

func (ir *IPRanger) ContainsAny(hosts ...string) bool {
	for _, host := range hosts {
		if ir.Contains(host) {
			return true
		}
	}
	return false
}

func (ir *IPRanger) Contains(host string) bool {
	ir.RLock()
	defer ir.RUnlock()

	// not valid => not contained
	if !ir.Np.Validate(host) {
		return false
	}

	// ip => check internal ip ranger
	if iputil.IsIP(host) {
		if ok, err := ir.iprangerop.Contains(net.ParseIP(host)); err == nil {
			return ok
		}
	}

	// fqdn, cidr => check hmap
	_, ok := ir.Hosts.Get(host)
	return ok
}

func (ir *IPRanger) Add(host string) error {
	// skip invalid
	if !ir.Np.Validate(host) {
		return errors.New("invalid host")
	}

	// skip already contained
	if ir.Contains(host) {
		return errors.New("host already added")
	}

	// ips: valid + new => add
	if iputil.IsIP(host) {
		if ir.Np.Validate(host) {
			return ir.add(host)
		}
		return errors.New("invalid ip")
	}

	return ir.add(host)
}

func (ir *IPRanger) asIPNet(host string) (*net.IPNet, error) {
	var (
		network *net.IPNet
		err     error
	)
	switch {
	case iputil.IsCIDR(host):
		_, network, err = net.ParseCIDR(host)
	case iputil.IsIPv4(host):
		network = iputil.AsIPV4IpNet(host)
	case iputil.IsIPv6(host):
		network = iputil.AsIPV6IpNet(host)
	default:
		err = errors.New("unsupported ip/cidr type")
	}

	return network, err
}

func (ir *IPRanger) add(host string) error {
	ir.Lock()
	defer ir.Unlock()

	if iputil.IsIP(host) || iputil.IsCIDR(host) {
		network, err := ir.asIPNet(host)
		if err != nil {
			return err
		}
		atomic.AddUint64(&ir.Stats.IPS, mapcidr.AddressCountIpnet(network))
		return ir.iprangerop.Insert(cidranger.NewBasicRangerEntry(*network))
	}

	return nil
}

func (ir *IPRanger) IsValid(host string) bool {
	return ir.Np.Validate(host)
}

func (ir *IPRanger) Delete(host string) error {
	// if it's an ip convert it to cidr representation
	if iputil.IsIP(host) || iputil.IsCIDR(host) {
		return ir.delete(host)
	}

	return errors.New("only ip or cidr supported")
}

func (ir *IPRanger) delete(host string) error {
	ir.Lock()
	defer ir.Unlock()

	network, err := ir.asIPNet(host)
	if err != nil {
		return err
	}

	atomic.AddUint64(&ir.Stats.IPS, -mapcidr.AddressCountIpnet(network))
	_, err = ir.iprangerop.Remove(*network)

	return err
}

func (ir *IPRanger) AddHostWithMetadata(host, metadata string) error {
	if !ir.IsValid(host) {
		return errors.New("invalid host with metadata")
	}
	// cache ip/cidr
	_ = ir.Add(host)

	// dedupe all the hosts and also keep track of ip => host for the output - just append new hostname
	if data, ok := ir.Hosts.Get(host); ok {
		// check if fqdn not contained
		datas := string(data)
		if datas != metadata && !stringsutil.ContainsAny(datas, metadata+",", ","+metadata+",", ","+metadata) {
			hosts := strings.Split(string(data), ",")
			hosts = append(hosts, metadata)
			atomic.AddUint64(&ir.Stats.Hosts, 1)
			return ir.Hosts.Set(host, []byte(strings.Join(hosts, ",")))
		}
		// host already contained
		return nil
	}
	atomic.AddUint64(&ir.Stats.Hosts, 1)
	return ir.Hosts.Set(host, []byte(metadata))
}

func (ir *IPRanger) HasIP(IP string) bool {
	_, ok := ir.Hosts.Get(IP)
	return ok
}

func (ir *IPRanger) GetHostsByIP(IP string) ([]string, error) {
	dt, ok := ir.Hosts.Get(IP)
	if ok {
		return strings.Split(string(dt), ","), nil
	}

	// if not found return the ip
	return []string{IP}, nil
}

func (ir *IPRanger) Close() error {
	return ir.Hosts.Close()
}

func (ir *IPRanger) Shrink() error {
	// shrink all the cidrs and ips (ipv4)
	var items []*net.IPNet
	ir.Hosts.Scan(func(item, _ []byte) error {
		ipnet, err := ir.asIPNet(string(item))
		if err != nil {
			return err
		}
		items = append(items, ipnet)
		return nil
	})
	ir.CoalescedIPV4, ir.CoalescedIPV6 = mapcidr.CoalesceCIDRs(items)
	// reset the internal ranger with the new data
	ir.iprangerop = cidranger.NewPCTrieRanger()
	atomic.StoreUint64(&ir.Stats.IPS, 0)
	return ir.addToTcpTrie(ir.CoalescedIPV4, ir.CoalescedIPV6)
}

func (ir *IPRanger) addToTcpTrie(coalescedIpGroups ...[]*net.IPNet) error {
	ir.Lock()
	defer ir.Unlock()

	for _, coalescedIpGroup := range coalescedIpGroups {
		for _, coalescedIP := range coalescedIpGroup {
			err := ir.iprangerop.Insert(cidranger.NewBasicRangerEntry(*coalescedIP))
			if err != nil {
				return err
			}
			atomic.AddUint64(&ir.Stats.IPS, mapcidr.AddressCountIpnet(coalescedIP))
		}
	}
	return nil
}
