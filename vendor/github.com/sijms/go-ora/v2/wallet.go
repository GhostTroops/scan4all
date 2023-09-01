package go_ora

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	_ "crypto/sha1"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

//type CertificateData
type wallet struct {
	file          string
	password      []byte
	salt          []byte
	sha1Iteration int
	algType       int
	credentials   []walletCredential
	certificates  [][]byte
	//certificates  []*x509.Certificate
	privateKeys         [][]byte
	certificateRequests [][]byte
	//Certificates  []*x509.Certificate
}
type walletCredential struct {
	dsn      string
	username string
	password string
}

// NewWallet create new wallet object from file path
func NewWallet(filePath string) (*wallet, error) {
	ret := new(wallet)
	ret.file = filePath
	err := ret.read()
	return ret, err
}

// read will read the file data decrypting file chunk to get wallet information
func (w *wallet) read() error {
	fileData, err := ioutil.ReadFile(w.file)
	if err != nil {
		return err
	}
	index := 0
	if !bytes.Equal(fileData[index:index+3], []byte{161, 248, 78}) {
		return errors.New("TCPS: Invalid SSL Wallet (Magic)")
	}
	index += 3
	autoLoginLocal := false
	switch fileData[index] {
	case 54:
		fallthrough
	case 55:
		index += 1
	case 56:
		autoLoginLocal = true
		index += 1
	default:
		return errors.New("invalid magic version")
	}
	num1 := binary.BigEndian.Uint32(fileData[index : index+4])
	index += 4
	size := binary.BigEndian.Uint32(fileData[index : index+4])
	index += 4
	if num1 != 6 {
		return errors.New("invalid wallet header version")
	}
	num3 := fileData[index]
	if num3 == 5 {

	} else if num3 == 6 {
		index++
		rgbKey := fileData[index : index+16]
		index += 16
		blk, err := aes.NewCipher(rgbKey)
		if err != nil {
			return err
		}
		dec := cipher.NewCBCDecrypter(blk, []byte{192, 52, 216, 49, 28, 2, 206, 248, 81, 240, 20, 75, 129, 237, 75, 242})
		passwordLen := int(size) - 1 - 16
		w.password = make([]byte, passwordLen)
		dec.CryptBlocks(w.password, fileData[index:index+passwordLen])
		index += passwordLen
		if autoLoginLocal {
			hostname, _ := os.Hostname()
			currentUser := getCurrentUser()
			if idx := strings.Index(hostname, "."); idx != -1 {
				hostname = hostname[:idx]
			}
			key := []byte(hostname + currentUser.Name)
			mac := hmac.New(sha1.New, key)
			mac.Write(w.password)
			tempPassword := mac.Sum(nil)
			for x := 0; x < len(tempPassword); x++ {
				tempPassword[x] = (tempPassword[x]+128)%128%127 + 1
			}
			w.password = tempPassword[:16]
		}
	} else if num3 == 0x35 {
		index++
		rgbKey, err := hex.DecodeString(string(fileData[index : index+16]))
		if err != nil {
			return err
		}
		index += 16

		blk, err := des.NewCipher(rgbKey)
		if err != nil {
			return err
		}
		dec := cipher.NewCBCDecrypter(blk, []byte{0, 0, 0, 0, 0, 0, 0, 0})
		temp, err := hex.DecodeString(string(fileData[index : index+0x30]))
		if err != nil {
			return err
		}
		index += 0x30
		output := make([]byte, len(temp))
		dec.CryptBlocks(output, temp)
		num := int(output[len(output)-1])
		cutLen := 0
		if num <= dec.BlockSize() {
			apply := true
			for x := len(output) - num; x < len(output); x++ {
				if output[x] != uint8(num) {
					apply = false
					break
				}
			}
			if apply {
				cutLen = int(output[len(output)-1])
			}
			w.password = output[:len(output)-cutLen]
		} else {
			w.password = output
		}
	} else {
		return errors.New("invalid wallet header")
	}
	err = w.readPKCS12(fileData[index:])
	if err != nil {
		if autoLoginLocal {
			return fmt.Errorf("can't read wallet with auto login local properties: %v", err)
		}
	}
	return err
}

func (w *wallet) readPKCS12(data []byte) error {
	encryptedData, err := w.decodeASN1(data)
	if err != nil {
		return err
	}
	return w.decrypt(encryptedData)
}

func convertToBigEndianUtf16(input []byte) []byte {
	temp := utf16.Encode([]rune(string(input)))
	output := make([]byte, 0, (len(temp)*2)+2)
	for x := 0; x < len(temp); x++ {
		tempByte := []byte{0, 0}
		binary.BigEndian.PutUint16(tempByte, temp[x])
		output = append(output, tempByte...)
	}
	output = append(output, 0, 0)
	return output
}

func (w *wallet) decrypt(encryptedData []byte) error {
	From := convertToBigEndianUtf16(w.password)
	fillAndAlignBuffer := func(input []byte) []byte {
		output := append(make([]byte, 0, 64), input...)
		size := 64 - (len(input) % 64)
		if size != 64 {
			for size >= len(input) {
				output = append(output, input...)
				size -= len(input)
			}
		}
		if size > 0 {
			output = append(output, input[:size]...)
		}
		return output
	}
	To2 := fillAndAlignBuffer(From)   //  append(make([]byte, 0, 64), From...)
	To3 := fillAndAlignBuffer(w.salt) // append(make([]byte, 0, 64), salt...)
	produceHash := func(buff1, buff2, buff3 []byte, iter int) []byte {
		hash := crypto.SHA1.New()
		hash.Write(buff1)
		hash.Write(buff2)
		hash.Write(buff3)
		result := hash.Sum(nil)
		for x := 0; x < iter-1; x++ {
			hash.Reset()
			hash.Write(result)
			result = hash.Sum(nil)
		}
		return result
	}
	hashKey1 := produceHash(bytes.Repeat([]byte{1}, 64), To3, To2, w.sha1Iteration)
	iv := append(make([]byte, 0), produceHash(bytes.Repeat([]byte{2}, 64), To3, To2, w.sha1Iteration)[:8]...)
	var key []byte
	switch w.algType {
	case 1:
		key = append(key, hashKey1[:5]...)
		return errors.New("RC2 wallet decryption is not supported")
	case 2:
		// key length = 24
		key = append(key, hashKey1...)
		To1 := fillAndAlignBuffer(hashKey1)
		num3 := 1
		num4 := 1
		num5 := 64
		for num5 > 0 {
			num5--
			num6 := num3 + int(To2[num5]) + int(To1[num5])
			To2[num5] = uint8(num6)
			num3 = num6 >> 8
			num7 := num4 + int(To3[num5]) + int(To1[num5])
			To3[num5] = uint8(num7)
			num4 = num7 >> 8
		}
		hashKey2 := produceHash(bytes.Repeat([]byte{1}, 64), To3, To2, w.sha1Iteration)
		key = append(key, hashKey2[:4]...)
		//fmt.Println(bytes.Equal(key, []byte{56, 91, 246, 64, 137, 26, 26, 12, 251, 136, 124, 85, 94, 207, 206, 250, 84, 246, 69, 165, 194, 0, 218, 46}))
		//fmt.Println(bytes.Equal(iv, []byte{110, 118, 222, 233, 79, 228, 184, 70}))
		blk, err := des.NewTripleDESCipher(key)
		if err != nil {
			return err
		}
		decr := cipher.NewCBCDecrypter(blk, iv)
		output := make([]byte, len(encryptedData))
		decr.CryptBlocks(output, encryptedData)
		// remove padding
		if int(output[len(output)-1]) <= blk.BlockSize() {
			num := int(output[len(output)-1])
			padding := bytes.Repeat([]byte{uint8(num)}, num)
			if bytes.Equal(output[len(output)-num:], padding) {
				output = output[:len(output)-num]
			}
		}
		return w.readCredentials(output)
	}
	return errors.New("unsupported algorithm type")
}

// readCredentials read dsn, usernames and passwords into walletCredentials array
func (w *wallet) readCredentials(input []byte) error {
	w.certificates = nil
	w.credentials = nil
	if input[1] == 130 {
		num2 := int(input[2])*256 + int(input[3])
		if len(input) < num2+4 {
			num3 := num2 + 4 - len(input)
			input = append(input, make([]byte, num3)...)
		}
	}
	type struct1 struct {
		Id   asn1.ObjectIdentifier
		Data asn1.RawValue
	}
	type WalletCredentialData struct {
		Id    string
		Value string
	}
	var (
		temp1 []struct1
		temp2 struct1
		temp3 WalletCredentialData
	)
	//objectType := 0
	_, err := asn1.Unmarshal(input, &temp1)
	if err != nil {
		return err
	}
	//var a []asn1.RawValue
	for _, tmp := range temp1 {
		// check the Id of the tmp first
		switch tmp.Id.String() {
		case "1.2.840.113549.1.12.10.1.5":
			_, err = asn1.Unmarshal(tmp.Data.Bytes, &temp2)
			if err != nil {
				return err
			}
			if temp2.Id.String() == "0.22.72.134.247.13.1.10" {
				// certificate request
				var a []byte
				_, err := asn1.Unmarshal(temp2.Data.Bytes, &a)
				if err != nil {
					return err
				}
				w.certificateRequests = append(w.certificateRequests, a)
			}
			if temp2.Id.String() != "1.2.840.113549.1.16.12.12" {
				continue
			}

			_, err = asn1.Unmarshal(temp2.Data.Bytes, &temp3)
			if err != nil {
				return err
			}
			r, err := regexp.Compile("(^.+)([0-9]+)")
			if err != nil {
				return err
			}
			matches := r.FindStringSubmatch(temp3.Id)
			if len(matches) != 3 {
				continue
			}
			length, err := strconv.Atoi(matches[2])
			if err != nil {
				continue
			}
			for len(w.credentials) < length {
				w.credentials = append(w.credentials, walletCredential{})
			}
			switch matches[1] {
			case "oracle.security.client.connect_string":
				w.credentials[length-1].dsn = temp3.Value
			case "oracle.security.client.username":
				w.credentials[length-1].username = temp3.Value
			case "oracle.security.client.password":
				w.credentials[length-1].password = temp3.Value
			default:
				return errors.New(fmt.Sprintf("cannot find entry for: %s", matches[1]))
			}
		case "1.2.840.113549.1.12.10.1.1":
			var a struct {
				Num int
				F1  struct {
					Id asn1.ObjectIdentifier
					F1 asn1.RawValue
				}
				PrivateKeyData []byte
			}
			_, err = asn1.Unmarshal(tmp.Data.Bytes, &a)
			if err != nil {
				return err
			}
			w.privateKeys = append(w.privateKeys, a.PrivateKeyData)
		case "1.2.840.113549.1.12.10.1.3":
			var a struct {
				Id asn1.ObjectIdentifier
				F1 struct {
					Data []byte
				} `asn1:"class:2,tag:0"`
			}
			_, err = asn1.Unmarshal(tmp.Data.Bytes, &a)
			if err != nil {
				return err
			}
			found := false
			for _, cert := range w.certificates {
				if bytes.Equal(cert, a.F1.Data) {
					found = true
					break
				}
			}
			if !found {
				w.certificates = append(w.certificates, a.F1.Data)
			}
		default:
			continue
		}

	}
	return nil
}

func (w *wallet) decodeASN1(buffer []byte) (encryptedData []byte, err error) {
	type IDBuffer struct {
		Id   asn1.ObjectIdentifier
		Data asn1.RawValue
	}
	type struct1 struct {
		Num  int
		Obj1 IDBuffer
		Obj2 struct {
			Obj struct {
				Obj  IDBuffer
				Data []byte
			}
			Data []byte
			Num  int
		}
	}
	type struct3 struct {
		Num int
		Obj struct {
			Id  asn1.ObjectIdentifier
			Obj struct {
				Id  asn1.ObjectIdentifier
				Obj struct {
					Salt         []byte
					IterateCount int
				}
			}
			EncryptedData asn1.RawValue
		}
	}
	var (
		temp1   struct1
		temp2   []IDBuffer
		temp3   struct3
		buffer2 []byte
	)
	_, err = asn1.Unmarshal(buffer, &temp1)
	if err != nil {
		return
	}
	if temp1.Num < 2 {
		err = errors.New("error in reading wallet")
		return
	}
	if temp1.Obj1.Id.String() != "1.2.840.113549.1.7.1" {
		err = errors.New(fmt.Sprintf("error in reading wallet: invalid object ID received: %s, want: %s",
			temp1.Obj1.Id.String(), "1.2.840.113549.1.7.1"))
		return
	}
	_, err = asn1.Unmarshal(temp1.Obj1.Data.Bytes, &buffer2)
	if err != nil {
		return
	}
	_, err = asn1.Unmarshal(buffer2, &temp2)
	if err != nil {
		return
	}
	var index = -1
	for idx, obj := range temp2 {
		if obj.Id.String() == "1.2.840.113549.1.7.6" {
			index = idx
			break
		}
	}
	if index == -1 {
		err = errors.New(fmt.Sprintf("error in reading wallet: object ID: %s is not present",
			"1.2.840.113549.1.7.6"))
		return
	}

	_, err = asn1.Unmarshal(temp2[index].Data.Bytes, &temp3)
	if err != nil {
		return
	}
	if temp3.Obj.Id.String() != "1.2.840.113549.1.7.1" {
		err = errors.New(fmt.Sprintf("error in reading wallet: invalid object ID received: %s, want: %s",
			temp3.Obj.Id.String(), "1.2.840.113549.1.7.1"))
		return
	}
	if temp3.Obj.Obj.Id.String() == "1.2.840.113549.1.12.1.3" {
		w.algType = 2 // "SHA1_3DES_CBC"
	} else if temp3.Obj.Obj.Id.String() == "1.2.840.113549.1.12.1.6" {
		w.algType = 1 // "SHA1_RC2_40_CBC"
	} else {
		err = errors.New("error in reading wallet: undefined algorithm type")
		return
	}
	w.salt = temp3.Obj.Obj.Obj.Salt
	encryptedData = temp3.Obj.EncryptedData.Bytes
	w.sha1Iteration = temp3.Obj.Obj.Obj.IterateCount
	return
}

// getCredential read one credential dsn, username, password from encrypted data
func (w *wallet) getCredential(server string, port int, service, username string) (*walletCredential, error) {
	rHost, err := regexp.Compile(`\(\s*HOST\s*=\s*([A-z0-9._%+-]+)\)`)
	if err != nil {
		return nil, err
	}
	rPort, err := regexp.Compile(`\(\s*PORT\s*=\s*([0-9]+)\)`)
	if err != nil {
		return nil, err
	}
	rService, err := regexp.Compile(`\(\s*SERVICE_NAME\s*=\s*([A-Z0-9._%+-]+)\)`)
	if err != nil {
		return nil, err
	}
	var (
		lhost    string
		lport    int
		lservice string
	)
	for _, cred := range w.credentials {
		if username != "" {
			if strings.ToUpper(username) != strings.ToUpper(cred.username) {
				continue
			}
		}
		matches := rHost.FindStringSubmatch(strings.ToUpper(cred.dsn))
		if len(matches) != 2 {
			continue
		}
		lhost = strings.TrimSpace(matches[1])
		matches = rPort.FindStringSubmatch(strings.ToUpper(cred.dsn))
		if len(matches) == 2 {
			lport, err = strconv.Atoi(matches[1])
			if err != nil {
				lport = defaultPort
			}
		} else {
			lport = defaultPort
		}
		matches = rService.FindStringSubmatch(strings.ToUpper(cred.dsn))
		if len(matches) != 2 {
			continue
		}
		lservice = strings.TrimSpace(matches[1])
		if port == 0 {
			port = 1521
		}
		if lhost == strings.ToUpper(server) &&
			lport == port &&
			lservice == strings.ToUpper(service) {
			return &cred, nil
		}
	}
	return nil, nil
}
