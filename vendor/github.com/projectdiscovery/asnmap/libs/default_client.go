package asnmap

var DefaultClient *Client

func init() {
	var err error
	DefaultClient, err = NewClient()
	if err != nil {
		// if we can't create the default client it makes sense to panic, as any other attempt will fail
		panic(err)
	}
}

func GetData(input string) ([]*Response, error) {
	return DefaultClient.GetData(input)
}
