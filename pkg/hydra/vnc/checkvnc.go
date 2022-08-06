package vnc

import (
	"fmt"
	"net"
)

func Check(Host, Username, Password string, Port int) (bool, error) {
	nc, err := net.Dial("tcp", fmt.Sprintf("%s:%d", Host, Port))
	if err != nil {
		return false, err
	}
	cc1, err := Client(nc, &ClientConfig{Auth: []ClientAuth{&PasswordAuth{Password: Password}}})
	if err != nil {
		return false, err
	} else {
		cc1.Close()
		return true, nil
	}
}
