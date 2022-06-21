package writer

import (
	"github.com/projectdiscovery/gologger/levels"
)

// Writer type writes data to an output type.
type Writer interface {
	// Write writes the data to an output writer.
	Write(data []byte, level levels.Level)
}
