package irc

// Handler is a simple interface meant for dispatching a message from
// a Client connection.
type Handler interface {
	Handle(*Client, *Message)
}

// HandlerFunc is a simple wrapper around a function which allows it
// to be used as a Handler.
type HandlerFunc func(*Client, *Message)

// Handle calls f(c, m)
func (f HandlerFunc) Handle(c *Client, m *Message) {
	f(c, m)
}
