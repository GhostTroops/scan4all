package customlist

import "github.com/hktalent/scan4all/pkg/httpx/common/fileutil"

const maxRecursion = 10

// CustomList for fastdialer
type CustomList []string

// String returns just a label
func (c *CustomList) String() string {
	return "Custom Global List"
}

// Set a new global header
func (c *CustomList) Set(value string) error {
	values := fileutil.LoadCidrsFromSliceOrFileWithMaxRecursion(value, ",", maxRecursion)
	*c = append(*c, values...)
	return nil
}
