package client

type Headers []Header

func (h Headers) Len() int { return len(h) }

func (h Headers) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h Headers) Less(i, j int) bool {
	switch {
	case h[i].Key < h[j].Key:
		return true
	case h[i].Key > h[j].Key:
		return false
	default:
		return h[i].Value < h[j].Value
	}
}
