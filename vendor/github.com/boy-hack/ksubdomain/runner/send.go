package runner

import (
	"github.com/boy-hack/ksubdomain/core/device"
	"github.com/boy-hack/ksubdomain/core/gologger"
	"github.com/boy-hack/ksubdomain/runner/statusdb"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"sync/atomic"
	"time"
)

func (r *runner) sendCycle() {
	for domain := range r.sender {
		r.limit.Take()
		v, ok := r.hm.Get(domain)
		if !ok {
			v = statusdb.Item{
				Domain:      domain,
				Dns:         r.choseDns(domain),
				Time:        time.Now(),
				Retry:       0,
				DomainLevel: 0,
			}
			r.hm.Add(domain, v)
		} else {
			v.Retry += 1
			v.Time = time.Now()
			v.Dns = r.choseDns(domain)
			r.hm.Set(domain, v)
		}
		send(domain, v.Dns, r.options.EtherInfo, r.dnsid, uint16(r.freeport), r.handle, r.dnsType)
		atomic.AddUint64(&r.sendIndex, 1)
	}
}
func send(domain string, dnsname string, ether *device.EtherTable, dnsid uint16, freeport uint16, handle *pcap.Handle, dnsType layers.DNSType) {
	DstIp := net.ParseIP(dnsname).To4()
	eth := &layers.Ethernet{
		SrcMAC:       ether.SrcMac.HardwareAddr(),
		DstMAC:       ether.DstMac.HardwareAddr(),
		EthernetType: layers.EthernetTypeIPv4,
	}
	// Our IPv4 header
	ip := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     0, // FIX
		Id:         0,
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0,
		TTL:        255,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      ether.SrcIp,
		DstIP:      DstIp,
	}
	// Our UDP header
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(freeport),
		DstPort: layers.UDPPort(53),
	}
	// Our DNS header
	dns := &layers.DNS{
		ID:      dnsid,
		QDCount: 1,
		RD:      true, //递归查询标识
	}
	dns.Questions = append(dns.Questions,
		layers.DNSQuestion{
			Name:  []byte(domain),
			Type:  dnsType,
			Class: layers.DNSClassIN,
		})
	// Our UDP header
	_ = udp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{
			ComputeChecksums: true, // automatically compute checksums
			FixLengths:       true,
		},
		eth, ip, udp, dns,
	)
	if err != nil {
		gologger.Warningf("SerializeLayers faild:%s\n", err.Error())
	}
	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		gologger.Warningf("WritePacketDate error:%s\n", err.Error())
	}
}
