package runner

import (
	"context"
	"errors"
	"fmt"
	"github.com/boy-hack/ksubdomain/runner/result"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"sync/atomic"
	"time"
)

func dnsRecord2String(rr layers.DNSResourceRecord) (string, error) {
	if rr.Class == layers.DNSClassIN {
		switch rr.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			if rr.IP != nil {
				return rr.IP.String(), nil
			}
		case layers.DNSTypeNS:
			if rr.NS != nil {
				return "NS " + string(rr.NS), nil
			}
		case layers.DNSTypeCNAME:
			if rr.CNAME != nil {
				return "CNAME " + string(rr.CNAME), nil
			}
		case layers.DNSTypePTR:
			if rr.PTR != nil {
				return "PTR " + string(rr.PTR), nil
			}
		case layers.DNSTypeTXT:
			if rr.TXT != nil {
				return "TXT " + string(rr.TXT), nil
			}
		}
	}
	return "", errors.New("dns record error")
}

func (r *runner) recvChanel(ctx context.Context) error {
	var (
		snapshotLen = 65536
		timeout     = -1 * time.Second
		err         error
	)
	inactive, err := pcap.NewInactiveHandle(r.options.EtherInfo.Device)
	if err != nil {
		return err
	}
	err = inactive.SetSnapLen(snapshotLen)
	if err != nil {
		return err
	}
	defer inactive.CleanUp()
	if err = inactive.SetTimeout(timeout); err != nil {
		return err
	}
	err = inactive.SetImmediateMode(true)
	if err != nil {
		return err
	}
	handle, err := inactive.Activate()
	if err != nil {
		return err
	}
	defer handle.Close()

	err = handle.SetBPFFilter(fmt.Sprintf("udp and src port 53 and dst port %d", r.freeport))
	if err != nil {
		return errors.New(fmt.Sprintf("SetBPFFilter Faild:%s", err.Error()))
	}

	// Listening

	var udp layers.UDP
	var dns layers.DNS
	var eth layers.Ethernet
	var ipv4 layers.IPv4
	var ipv6 layers.IPv6

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet, &eth, &ipv4, &ipv6, &udp, &dns)

	var data []byte
	var decoded []gopacket.LayerType
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			data, _, err = handle.ReadPacketData()
			if err != nil {
				continue
			}
			err = parser.DecodeLayers(data, &decoded)
			if err != nil {
				continue
			}
			if !dns.QR {
				continue
			}
			if dns.ID != r.dnsid {
				continue
			}
			atomic.AddUint64(&r.recvIndex, 1)
			if len(dns.Questions) == 0 {
				continue
			}
			subdomain := string(dns.Questions[0].Name)
			r.hm.Del(subdomain)
			if dns.ANCount > 0 {
				atomic.AddUint64(&r.successIndex, 1)
				var answers []string
				for _, v := range dns.Answers {
					answer, err := dnsRecord2String(v)
					if err != nil {
						continue
					}
					answers = append(answers, answer)
				}
				r.recver <- result.Result{
					Subdomain: subdomain,
					Answers:   answers,
				}
			}
		}
	}
}
