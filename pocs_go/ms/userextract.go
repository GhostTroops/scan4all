package ms

import (
	"bytes"
	"crypto/md5"
	"errors"
	"io"
)

type user struct {
	username string
	pass     string
}

func getUsersAandDecryptPasswords(data []byte) ([]user, error) {
	var results []user
	sliceData := bytes.Split(data, []byte("M2"))[1:]

	for _, data := range sliceData {
		name, pass, err := extractUserAndPassword(data)
		if err != nil {
			continue
		}
		passowrd, err := decryptPass(name, pass)
		if err != nil {
			return nil, err
		}
		results = append(results, user{username: string(name), pass: string(passowrd)})
	}
	return results, nil
}
func extractUserAndPassword(data []byte) (name []byte, pass []byte, err error) {
	err = errors.New("could not extract users")
	username := bytes.Split(data, []byte("\x01\x00\x00\x21"))
	userpass := bytes.Split(data, []byte("\x11\x00\x00\x21"))
	if len(username) != 1 && len(userpass) != 1 {
		usernameLen := username[1][0]
		userpassLen := userpass[1][0]
		name = username[1][1 : 1+int(usernameLen)]
		pass = userpass[1][1 : 1+int(userpassLen)]
		return name, pass, nil
	}
	return nil, nil, err
}
func decryptPass(name []byte, encryptpass []byte) ([]byte, error) {
	var pass []byte
	magicKey := []byte("283i4jfkai3389") // 51pwn_scan4all_
	data := md5.New()
	if _, err := io.WriteString(data, string(name)+string(magicKey)); err != nil {
		return nil, err
	}
	digitKey := data.Sum(nil)
	for i := range encryptpass {
		pass = append(pass, encryptpass[i]^digitKey[i%len(digitKey)])
	}
	return pass, nil
}
