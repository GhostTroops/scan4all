package lib

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	util "github.com/hktalent/go-utils"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

var PublicKeys []string
var szPwd string

// 判断文件是否存在
func FileExists(s string) bool {
	if _, err := os.Stat(s); err == nil {
		return true
	}
	return false
}

func init() {
	util.RegInitFunc(func() {
		s, err := os.Getwd()
		if nil != err {
			log.Println("os.Getwd err: ", err)
		}
		szPwd = s
		LoadKeys()
	})
}

// 加载验证签名的key
func LoadKeys() {
	szPath := szPwd + "/config/"
	szLstKey := ""
	for _, k := range []string{"key2", "key1"} {
		szF := szPath + k
		if FileExists(szF) {
			data, err := ioutil.ReadFile(szF)
			if nil == err {
				s := strings.TrimSpace(string(data))
				if szLstKey != s {
					PublicKeys = append(PublicKeys, s)
					szLstKey = s
				}
			}
		}
	}
}

// 保存key
//
//	如果key2存在，则用key2覆盖key1
//	当前key始终保存到key2
func SaveKey(s string) (bool, error) {
	for _, k1 := range PublicKeys {
		if s == k1 {
			return false, errors.New("当前public key已经存在，无需重复更新")
		}
	}
	szPath := szPwd + "/config/"
	szF := szPath + "key2"
	if FileExists(szF) {
		data, err := ioutil.ReadFile(szF)
		if nil == err {
			ioutil.WriteFile(szPath+"key1", data, os.ModePerm)
		}
	}
	if err := ioutil.WriteFile(szF, []byte(s), os.ModePerm); err != nil {
		return false, err
	}
	PublicKeys = append([]string{strings.TrimSpace(s)}, PublicKeys...)
	return true, nil
}

/***************************************************************
* RSA 签名验证
* src:待验证的字串，sign:支付宝返回的签名
* pass:返回true表示验证通过
* err :当pass返回false时，err是出错的原因
****************************************************************/
func RSAVerify(src []byte, sign []byte, publicKey string) (pass bool, err error) {
	//步骤1，加载RSA的公钥
	block, _ := pem.Decode([]byte(publicKey))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Printf("Failed to parse RSA public key: %s\n", err)
		return
	}
	rsaPub, _ := pub.(*rsa.PublicKey)

	//步骤2，计算待签名字串的SHA1哈希
	t := sha1.New()
	io.WriteString(t, string(src))
	digest := t.Sum(nil)

	//步骤3，base64 decode,必须步骤，支付宝对返回的签名做过base64 encode必须要反过来decode才能通过验证
	data, _ := base64.StdEncoding.DecodeString(string(sign))

	//hexSig := hex.EncodeToString(data)
	//fmt.Printf("base decoder: %v, %v\n", string(sign), hexSig)

	//步骤4，调用rsa包的VerifyPKCS1v15验证签名有效性
	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA1, digest, data)
	if err != nil {
		//fmt.Println("Verify sig error, reason: ", err)
		return false, err
	}

	return true, nil
}

func GetSig(src string, prvKey []byte) string {
	signData := RsaSignWithSha1([]byte(src), prvKey)
	return strings.ReplaceAll(base64.StdEncoding.EncodeToString(signData), "\n", "")
}

// 数字签名检查
// Rsa 签名算法
func CheckSign(src, sign string) bool {
	for _, key := range PublicKeys {
		pass, err := RSAVerify([]byte(src), []byte(sign), key)
		if nil != err {
			log.Println("CheckSign = ", err)
		}
		if pass {
			return true
		}
	}
	return false
}
