package message

type LdapError struct {
	Msg string
}

func (err LdapError) Error() string {
	return err.Msg
}
