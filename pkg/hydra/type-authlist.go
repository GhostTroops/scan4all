package hydra

import (
	"github.com/GhostTroops/scan4all/pkg/kscan/lib/misc"
)

type AuthList struct {
	Username []string
	Password []string
	Special  []Auth
}

func NewAuthList() *AuthList {
	a := &AuthList{}
	a.Special = []Auth{}
	return a
}

func (a *AuthList) IsEmpty() bool {
	if len(a.Username) > 0 || len(a.Password) > 0 {
		return false
	}
	return true
}

func (a *AuthList) Merge(list *AuthList) {
	a.Username = append(a.Username, list.Username...)
	a.Password = append(a.Password, list.Password...)
	a.Special = append(a.Special, list.Special...)
	a.Username = misc.RemoveDuplicateElement(a.Username)
	a.Password = misc.RemoveDuplicateElement(a.Password)
}

func (a *AuthList) Replace(list *AuthList) {
	if len(list.Username) > 0 {
		a.Username = list.Username
	}
	if len(list.Password) > 0 {
		a.Password = list.Password
	}
	a.Special = list.Special
	a.Username = misc.RemoveDuplicateElement(a.Username)
	a.Password = misc.RemoveDuplicateElement(a.Password)
}

func (a *AuthList) Length() int {
	if len(a.Username) == 0 {
		return len(a.Password) + len(a.Special)
	}
	return (len(a.Password) * len(a.Username)) + len(a.Special)
}

func (a *AuthList) Dict(onlyPassword bool) []Auth {
	var dict []Auth
	dict = append(dict, a.Special...)
	if onlyPassword {
		dict = append(dict, NewAuthFromPasswords(a.Password)...)
	} else {
		dict = append(dict, NewAuthFromUsernameAndPassword(a.Username, a.Password)...)
	}
	//log.Println("Dict: ", len(dict), " onlyPassword = ", onlyPassword)
	return dict
}
