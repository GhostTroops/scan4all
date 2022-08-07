package irc

import (
	"fmt"
	"gopkg.in/irc.v3"
	"net"
)

func Check(Host, Username, Password string, Port int) (bool, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", Host, Port))
	bRst := false
	if err != nil {
		return bRst, err
	}

	config := irc.ClientConfig{
		Nick: Username,
		Pass: Password,
		User: Username,
		Name: Username,
		Handler: irc.HandlerFunc(func(c *irc.Client, m *irc.Message) {
			if m.Command == "001" { // 001 is a welcome event, so we join channels there
				bRst = true
			} else if m.Command == "PRIVMSG" && c.FromChannel(m) {
				bRst = false
			}
		}),
	}
	// Create the client
	client := irc.NewClient(conn, config)
	err = client.Run()
	if err == nil {
		return true, nil
	}
	return bRst, err
}
