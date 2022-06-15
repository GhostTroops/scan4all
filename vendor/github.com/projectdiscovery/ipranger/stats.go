package ipranger

type Stats struct {
	Hosts uint64
	IPS   uint64
	Ports uint64
}

func (s Stats) Total() uint64 {
	return s.Hosts + s.IPS
}
