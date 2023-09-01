package disk

const Megabyte = 1 << 20

var (
	OpenPogrebDB func(string) (DB, error)
)
