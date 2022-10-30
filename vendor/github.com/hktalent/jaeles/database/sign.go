package database

import (
	"fmt"
	"github.com/hktalent/jaeles/utils"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"github.com/hktalent/jaeles/database/models"
	"github.com/hktalent/jaeles/libs"
)

// CleanSigns clean all signature
func CleanSigns() {
	var signs []models.Signature
	DB.Find(&signs)
	DB.Unscoped().Delete(&signs)
}

// SelectSign select signature to gen request
func SelectSign(signName string) []string {
	var signs = []models.Signature{}
	DB.Find(&signs)

	if signName == "*" || signName == "" {
		fmt.Fprintf(os.Stderr, "[Warning] You literally just select ALL signatures. I hope you know what are you doing.\n")
	}
	//	DB.Find(&signs)
	//} else {
	//	DB.Where("sign_id LIKE ? OR name LIKE ?", fmt.Sprintf("%%%v%%", signName), fmt.Sprintf("%%%v%%", signName)).Find(&signs)
	//}

	var selectedSigns []string
	for _, sign := range signs {
		if signName == "*" || signName == "" {
			selectedSigns = append(selectedSigns, sign.AsbPath)
			continue
		}
		// grep info
		info := fmt.Sprintf("%v|%v|%v|tech:%v", sign.SignID, strings.ToLower(sign.Name), sign.AsbPath, sign.Tech)
		if strings.Contains(strings.ToLower(info), strings.ToLower(signName)) {
			selectedSigns = append(selectedSigns, sign.AsbPath)
			continue
		}
		r, err := regexp.Compile(signName)
		if err == nil {
			if r.MatchString(info) {
				selectedSigns = append(selectedSigns, sign.AsbPath)
			}
		}
	}
	return selectedSigns
}

// ImportSign import signature to DB
func ImportSign(signPath string) error {
	sign, err := ParseSignature(signPath)
	if err != nil {
		return fmt.Errorf("error parse sign: %v", err)
	}

	if sign.Info.Category == "" {
		if strings.Contains(sign.ID, "-") {
			sign.Info.Category = strings.Split(sign.ID, "-")[0]
		} else {
			sign.Info.Category = sign.ID
		}
	}
	if sign.Info.Name == "" {
		sign.Info.Name = sign.ID
	}

	signObj := models.Signature{
		Name:     sign.Info.Name,
		Category: sign.Info.Category,
		Risk:     sign.Info.Risk,
		Tech:     sign.Info.Tech,
		OS:       sign.Info.OS,
		SignID:   sign.ID,
		AsbPath:  signPath,
		Type:     sign.Type,
	}
	DB.Create(&signObj)
	return nil
}

// ParseSign parsing YAML signature file
func ParseSignature(signFile string) (sign libs.Signature, err error) {
	yamlFile, err := ioutil.ReadFile(signFile)
	if err != nil {
		utils.ErrorF("yamlFile.Get err  #%v - %v", err, signFile)
	}
	err = yaml.Unmarshal(yamlFile, &sign)
	if err != nil {
		utils.ErrorF("Error: %v - %v", err, signFile)
	}
	// set some default value
	if sign.Info.Category == "" {
		if strings.Contains(sign.ID, "-") {
			sign.Info.Category = strings.Split(sign.ID, "-")[0]
		} else {
			sign.Info.Category = sign.ID
		}
	}
	if sign.Info.Name == "" {
		sign.Info.Name = sign.ID
	}
	if sign.Info.Risk == "" {
		sign.Info.Risk = "Potential"
	}
	return sign, err
}
