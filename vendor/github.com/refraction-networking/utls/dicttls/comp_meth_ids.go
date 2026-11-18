package dicttls

// source: https://www.iana.org/assignments/comp-meth-ids/comp-meth-ids-2.csv
// last updated: March 2023

const (
	CompMeth_NULL    uint8 = 0
	CompMeth_DEFLATE uint8 = 1
	CompMeth_LZS     uint8 = 64
)

var DictCompMethValueIndexed = map[uint8]string{
	0:  "NULL",
	1:  "DEFLATE",
	64: "LZS",
}

var DictCompMethNameIndexed = map[string]uint8{
	"NULL":    0,
	"DEFLATE": 1,
	"LZS":     64,
}
