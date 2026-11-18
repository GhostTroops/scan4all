package writer

import (
	"os"
	"sync"

	"github.com/projectdiscovery/gologger/levels"
)

// CLI is a concurrent output writer to terminal.
type CLI struct {
	mutex *sync.Mutex
}

var _ Writer = &CLI{}

// NewCLI returns a new CLI concurrent log writer.
func NewCLI() *CLI {
	return &CLI{mutex: &sync.Mutex{}}
}

// WriteString writes an output to the underlying file
func (w *CLI) Write(data []byte, level levels.Level) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	switch level {
	case levels.LevelSilent:
		_, _ = os.Stdout.Write(data)
		_, _ = os.Stdout.WriteString(NewLine)
	default:
		_, _ = os.Stderr.Write(data)
		_, _ = os.Stderr.WriteString(NewLine)
	}
}
