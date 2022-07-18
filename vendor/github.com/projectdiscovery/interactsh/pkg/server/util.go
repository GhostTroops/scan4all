package server

import (
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/rs/xid"
)

func (options *Options) isCorrelationID(s string) bool {
	if len(s) == options.GetIdLength() && govalidator.IsAlphanumeric(s) {
		// xid should be 12
		if options.CorrelationIdLength != 12 {
			return true
		} else if _, err := xid.FromString(strings.ToLower(s[:options.CorrelationIdLength])); err == nil {
			return true
		}
	}
	return false
}
