package clistats

// DefaultOptions for clistats
var DefaultOptions = Options{
	ListenPort: 63636,
	Web:        true,
}

// Options to customize behavior
type Options struct {
	ListenPort int
	Web        bool
}
