package sources

type Query struct {
	Query string
	Limit int
}

type Agent interface {
	Query(*Session, *Query) (chan Result, error)
	Name() string
}
