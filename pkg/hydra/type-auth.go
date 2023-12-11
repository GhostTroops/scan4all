package hydra

import (
	"github.com/GhostTroops/scan4all/lib/util"
	"strings"
)

type Auth struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Other    map[string]string
}

func NewAuth() Auth {
	a := Auth{
		Username: "",
		Password: "",
		Other:    make(map[string]string),
	}
	return a
}

func NewAuthFromPasswords(passwords []string) []Auth {
	var auths []Auth
	for _, password := range passwords {
		auths = append(auths, NewSpecialAuth("", password))
	}
	return auths
}

func NewAuthFromUsernameAndPassword(usernames, passwords []string) []Auth {
	var auths []Auth
	for _, password := range passwords {
		for _, username := range usernames {
			auths = append(auths, NewSpecialAuth(username, password))
		}
	}
	return auths
}

func NewSpecialAuth(username, password string) Auth {
	a := NewAuth()
	a.Username = username
	a.Password = password
	return a
}

func (a *Auth) MakePassword() {
	if util.StrContains(a.Password, "%user%") {
		a.Password = strings.ReplaceAll(a.Password, "%user%", a.Username)
	}
}
