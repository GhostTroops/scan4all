package hydra

import (
	"fmt"
	"github.com/GhostTroops/scan4all/pkg/kscan/lib/color"
)

type AuthInfo struct {
	Protocol string `json:"Protocol"`
	Port     int    `json:"Port"`
	IPAddr   string `json:"IPAddr"`
	Auth     Auth   `json:"Auth,omitempty"`
	Status   bool   `json:"status,omitempty"`
}

func NewAuthInfo(IPAddr string, Port int, Protocol string) *AuthInfo {
	a := &AuthInfo{
		Protocol: Protocol,
		Port:     Port,
		IPAddr:   IPAddr,
	}
	a.Auth = NewAuth()
	a.Status = false
	return a
}

func (a *AuthInfo) Display() string {
	URL := fmt.Sprintf("%s://%s:%d", a.Protocol, a.IPAddr, a.Port)
	authChar := ""
	outMap := a.Auth.Other
	if a.Auth.Username != "" {
		outMap["Username"] = a.Auth.Username
	}
	if a.Auth.Password != "" {
		outMap["Password"] = a.Auth.Password
	}
	for key, value := range outMap {
		authChar += fmt.Sprintf("%s:%s、", key, value)
	}
	authChar = authChar[:len(authChar)-3]
	var s string
	s = fmt.Sprintf("%-30v %-26v %v", URL, "Success", authChar)
	s = color.Red(s)
	s = color.Overturn(s)
	return s
}

func (a *AuthInfo) Output() string {
	URL := fmt.Sprintf("%s://%s:%d", a.Protocol, a.IPAddr, a.Port)
	authChar := ""
	if a.Auth.Username == "" {
		authChar = fmt.Sprintf("Password:%s", a.Auth.Password)
	} else {
		authChar = fmt.Sprintf("Username:%s、Password:%s", a.Auth.Username, a.Auth.Password)
	}
	for key, value := range a.Auth.Other {
		authChar += fmt.Sprintf("、%s:%s", key, value)
	}
	var s string
	s = fmt.Sprintf("%-30v %-26v %v", URL, "Success", authChar)
	return s
}
