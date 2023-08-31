package errorutil

type ErrorLevel uint

const (
	Panic ErrorLevel = iota
	Fatal
	Runtime // Default
)

func (l ErrorLevel) String() string {
	switch l {
	case Panic:
		return "PANIC"
	case Fatal:
		return "FATAL"
	case Runtime:
		return "RUNTIME"
	}
	return "RUNTIME" //default is runtime
}
