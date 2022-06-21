package hydra

import "strings"

type Auth struct {
	Username string
	Password string
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
	if strings.Contains(a.Password, "%user%") {
		a.Password = strings.ReplaceAll(a.Password, "%user%", a.Username)
	}
}
