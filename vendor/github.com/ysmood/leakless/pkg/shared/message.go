package shared

// Message send between guard processes
type Message struct {
	UID   string
	PID   int
	Error string
}
