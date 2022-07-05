package message

type Writable interface {
	write(bytes *Bytes) int
	writeTagged(bytes *Bytes, class int, tag int) int
}
