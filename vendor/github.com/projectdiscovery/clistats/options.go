package clistats

// DefaultOptions for clistats
var DefaultOptions = Options{
	ListenHost: "127.0.0.1",
	ListenPort: 63636,
	Web:        true,
}

// Options to customize behavior
type Options struct {
	ListenHost string
	ListenPort int
	Web        bool
}
