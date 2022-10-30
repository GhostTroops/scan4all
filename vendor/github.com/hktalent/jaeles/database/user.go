package database

import (
	"crypto/sha1"
	"fmt"
	"github.com/hktalent/jaeles/utils"
	"strconv"
	"time"

	"github.com/hktalent/jaeles/database/models"
)

// SelectUser get password of one user to compare
func SelectUser(username string) string {
	var user models.User
	DB.Where("username = ?", username).First(&user)
	if user.Username == username {
		return user.Password
	}
	return ""
}

// CreateUser used to create new user
func CreateUser(username string, password string) {
	oldpass := SelectUser(username)
	if oldpass != "" {
		UpdateUser(username, password)
	} else {
		rawToken := fmt.Sprintf("%v-%v", username, strconv.FormatInt(time.Now().Unix(), 10))
		rawSecret := fmt.Sprintf("%v-%v-%v", username, password, strconv.FormatInt(time.Now().Unix(), 10))

		userObj := models.User{
			Username: username,
			Email:    username,
			Password: GenHash(password),
			Secret:   GenHash(rawSecret),
			Token:    GenHash(rawToken),
		}
		utils.GoodF("Create new credentials %v:%v", username, password)

		DB.Create(&userObj)
	}
}

// UpdateUser update default sign
func UpdateUser(username string, password string) {
	var userObj models.User
	DB.Where("username = ?", username).First(&userObj)
	userObj.Password = GenHash(password)
	DB.Save(&userObj)
}

// GenHash generate SHA1 hash
func GenHash(text string) string {
	h := sha1.New()
	h.Write([]byte(text))
	hashed := h.Sum(nil)
	return fmt.Sprintf("%x", hashed)
}
