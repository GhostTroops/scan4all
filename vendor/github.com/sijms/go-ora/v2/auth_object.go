package go_ora

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/sijms/go-ora/v2/network"
	"github.com/sijms/go-ora/v2/network/security"
	"strconv"
	"strings"
	"time"
)

// E infront of the variable means encrypted
type AuthObject struct {
	EServerSessKey   string
	EClientSessKey   string
	EPassword        string
	ESpeedyKey       string
	ServerSessKey    []byte
	ClientSessKey    []byte
	KeyHash          []byte
	Salt             string
	pbkdf2ChkSalt    string
	pbkdf2VgenCount  int
	pbkdf2SderCount  int
	globalUniqueDBID string
	usePadding       bool
	customHash       bool
	VerifierType     int
	tcpNego          *TCPNego
}

// create authentication object through reading data from network
func newAuthObject(username string, password string, tcpNego *TCPNego, conn *Connection) (*AuthObject, error) {
	session := conn.session
	ret := new(AuthObject)
	ret.tcpNego = tcpNego
	ret.usePadding = false
	ret.customHash = ret.tcpNego.ServerCompileTimeCaps[4]&32 != 0
	loop := true
	for loop {
		messageCode, err := session.GetByte()
		if err != nil {
			return nil, err
		}
		switch messageCode {
		//case 4:
		//	session.Summary, err = network.NewSummary(session)
		//	if err != nil {
		//		return nil, err
		//	}
		//	if session.HasError() {
		//		return nil, session.GetError()
		//	}
		//	loop = false
		case 8:
			dictLen, err := session.GetInt(4, true, true)
			if err != nil {
				return nil, err
			}
			for x := 0; x < dictLen; x++ {
				key, val, num, err := session.GetKeyVal()
				if err != nil {
					return nil, err
				}
				if bytes.Compare(key, []byte("AUTH_SESSKEY")) == 0 {
					if len(ret.EServerSessKey) == 0 {
						ret.EServerSessKey = string(val)
					}
				} else if bytes.Compare(key, []byte("AUTH_VFR_DATA")) == 0 {
					if len(ret.Salt) == 0 {
						ret.Salt = string(val)
						ret.VerifierType = num
					}
				} else if bytes.Compare(key, []byte("AUTH_PBKDF2_CSK_SALT")) == 0 {
					if len(ret.pbkdf2ChkSalt) == 0 {
						ret.pbkdf2ChkSalt = string(val)
						if len(ret.pbkdf2ChkSalt) != 32 {
							return nil, &network.OracleError{
								ErrCode: 28041,
								ErrMsg:  "ORA-28041: Authentication protocol internal error",
							}
						}
					}
				} else if bytes.Compare(key, []byte("AUTH_PBKDF2_VGEN_COUNT")) == 0 {
					if ret.pbkdf2VgenCount == 0 {
						ret.pbkdf2VgenCount, err = strconv.Atoi(string(val))
						if err != nil {
							return nil, &network.OracleError{
								ErrCode: 28041,
								ErrMsg:  "ORA-28041: Authentication protocol internal error",
							}
						}
						if ret.pbkdf2VgenCount < 4096 || ret.pbkdf2VgenCount > 100000000 {
							ret.pbkdf2VgenCount = 4096
						}
					}
				} else if bytes.Compare(key, []byte("AUTH_PBKDF2_SDER_COUNT")) == 0 {
					ret.pbkdf2SderCount, err = strconv.Atoi(string(val))
					if ret.pbkdf2SderCount == 0 {
						if err != nil {
							return nil, &network.OracleError{
								ErrCode: 28041,
								ErrMsg:  "ORA-28041: Authentication protocol internal error",
							}
						}
						if ret.pbkdf2SderCount < 3 || ret.pbkdf2SderCount > 100000000 {
							ret.pbkdf2SderCount = 3
						}
					}
				}
			}
		//case 15:
		//	warning, err := network.NewWarningObject(conn.session)
		//	if err != nil {
		//		return nil, err
		//	}
		//	if warning != nil {
		//		fmt.Println(warning)
		//	}
		//case 23:
		//	opCode, err := conn.session.GetByte()
		//	if err != nil {
		//		return nil, err
		//	}
		//	err = conn.getServerNetworkInformation(opCode)
		//	if err != nil {
		//		return nil, err
		//	}
		default:
			err = conn.readResponse(messageCode)
			if err != nil {
				return nil, err
			}
			if messageCode == 4 {
				if session.HasError() {
					return nil, session.GetError()
				}
				loop = false
			}
			//return nil, errors.New(fmt.Sprintf("message code error: received code %d and expected code is 8", messageCode))
		}
	}
	if len(ret.EServerSessKey) != 64 && len(ret.EServerSessKey) != 96 {
		return nil, errors.New("session key should be either 64, 96 bytes long")
	}
	var key []byte
	var speedyKey []byte
	padding := false
	var err error

	if ret.VerifierType == 2361 {
		key, err = getKeyFromUserNameAndPassword(username, password)
		if err != nil {
			return nil, err
		}
	} else if ret.VerifierType == 6949 {

		if ret.tcpNego.ServerCompileTimeCaps[4]&2 == 0 {
			padding = true
		}
		result, err := hex.DecodeString(ret.Salt)
		if err != nil {
			return nil, err
		}
		result = append([]byte(password), result...)
		hash := sha1.New()
		_, err = hash.Write(result)
		if err != nil {
			return nil, err
		}
		key = hash.Sum(nil)           // 20 byte key
		key = append(key, 0, 0, 0, 0) // 24 byte key
	} else if ret.VerifierType == 18453 {
		salt, err := hex.DecodeString(ret.Salt)
		if err != nil {
			return nil, err
		}
		message := append(salt, []byte("AUTH_PBKDF2_SPEEDY_KEY")...)
		speedyKey = generateSpeedyKey(message, []byte(password), ret.pbkdf2VgenCount)

		buffer := append(speedyKey, salt...)
		hash := sha512.New()
		hash.Write(buffer)
		key = hash.Sum(nil)[:32]
	} else {
		return nil, errors.New("unsupported verifier type")
	}
	// get the server session key
	ret.ServerSessKey, err = decryptSessionKey(padding, key, ret.EServerSessKey)
	if err != nil {
		return nil, err
	}

	// note if serverSessKey length is less than the expected length according to verifier generate random one
	// generate new key for client
	ret.ClientSessKey = make([]byte, len(ret.ServerSessKey))
	for {
		_, err = rand.Read(ret.ClientSessKey)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(ret.ClientSessKey, ret.ServerSessKey) {
			break
		}
	}

	// encrypt the client key
	ret.EClientSessKey, err = encryptSessionKey(padding, key, ret.ClientSessKey)
	if err != nil {
		return nil, err
	}

	// get the hash key form server and client session key
	newKey, err := ret.generatePasswordEncKey()
	if err != nil {
		return nil, err
	}
	if ret.VerifierType == 18453 {
		padding = false
	} else {
		padding = true
	}
	// encrypt the password
	ret.EPassword, err = encryptPassword([]byte(password), newKey, true)
	if err != nil {
		return nil, err
	}
	if ret.VerifierType == 18453 {
		ret.ESpeedyKey, err = encryptPassword(speedyKey, newKey, padding)
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

// write authentication data to network
func (obj *AuthObject) Write(connOption *network.ConnectionOption, mode LogonMode, session *network.Session) error {
	var keys = make([]string, 0, 20)
	var values = make([]string, 0, 20)
	var flags = make([]uint8, 0, 20)
	appendKeyVal := func(key, val string, f uint8) {
		keys = append(keys, key)
		values = append(values, val)
		flags = append(flags, f)
	}
	index := 0
	if len(obj.EClientSessKey) > 0 {
		appendKeyVal("AUTH_SESSKEY", obj.EClientSessKey, 1)
		index++
	}
	if len(obj.EPassword) > 0 {
		appendKeyVal("AUTH_PASSWORD", obj.EPassword, 0)
		index++
	}
	if len(obj.ESpeedyKey) > 0 {
		appendKeyVal("AUTH_PBKDF2_SPEEDY_KEY", obj.ESpeedyKey, 0)
		index++
	}
	appendKeyVal("AUTH_TERMINAL", connOption.ClientInfo.HostName, 0)
	index++
	appendKeyVal("AUTH_PROGRAM_NM", connOption.ClientInfo.ProgramName, 0)
	index++
	appendKeyVal("AUTH_MACHINE", connOption.ClientInfo.HostName, 0)
	index++
	appendKeyVal("AUTH_PID", fmt.Sprintf("%d", connOption.ClientInfo.PID), 0)
	index++
	appendKeyVal("AUTH_SID", connOption.ClientInfo.UserName, 0)
	index++
	appendKeyVal("AUTH_CONNECT_STRING", connOption.ConnectionData(), 0)
	index++
	appendKeyVal("SESSION_CLIENT_CHARSET", strconv.Itoa(int(obj.tcpNego.ServerCharset)), 0)
	index++
	appendKeyVal("SESSION_CLIENT_LIB_TYPE", "0", 0)
	index++
	appendKeyVal("SESSION_CLIENT_DRIVER_NAME", connOption.ClientInfo.DriverName, 0)
	index++
	appendKeyVal("SESSION_CLIENT_VERSION", "2.0.0.0", 0)
	index++
	appendKeyVal("SESSION_CLIENT_LOBATTR", "1", 0)
	index++
	_, offset := time.Now().Zone()
	tz := ""
	if offset == 0 {
		tz = "00:00"
	} else {
		hours := int8(offset / 3600)

		minutes := int8((offset / 60) % 60)
		if minutes < 0 {
			minutes = minutes * -1
		}
		tz = fmt.Sprintf("%+03d:%02d", hours, minutes)
	}
	appendKeyVal("AUTH_ALTER_SESSION",
		fmt.Sprintf("ALTER SESSION SET NLS_LANGUAGE='%s' NLS_TERRITORY='%s'  TIME_ZONE='%s'\x00",
			connOption.Language, connOption.Territory, tz), 1)
	index++
	if len(connOption.ProxyClientName) > 0 {
		appendKeyVal("PROXY_CLIENT_NAME", connOption.ProxyClientName, 0)
		index++
	}
	session.ResetBuffer()
	session.PutBytes(3, 0x73, 0)
	if len(connOption.UserID) > 0 {
		session.PutBytes(1)
		session.PutInt(len(connOption.UserID), 4, true, true)
	} else {
		session.PutBytes(0, 0)
	}
	// if proxy auth logonMode |= 0x400
	if len(connOption.UserID) > 0 && len(obj.EPassword) > 0 {
		mode |= UserAndPass
	}
	session.PutUint(int(mode|NoNewPass), 4, true, true)
	session.PutBytes(1)
	session.PutUint(index, 4, true, true)
	session.PutBytes(1, 1)
	if len(connOption.UserID) > 0 {
		session.PutString(connOption.UserID)
	}
	for i := 0; i < index; i++ {
		session.PutKeyValString(keys[i], values[i], flags[i])
	}
	return session.Write()

}

func generateSpeedyKey(buffer, key []byte, turns int) []byte {

	mac := hmac.New(sha512.New, key)
	mac.Write(append(buffer, 0, 0, 0, 1))
	firstHash := mac.Sum(nil)
	tempHash := make([]byte, len(firstHash))
	copy(tempHash, firstHash)
	for index1 := 2; index1 <= turns; index1++ {
		//mac = hmac.New(sha512.New, []byte("ter1234"))
		mac.Reset()
		mac.Write(tempHash)
		tempHash = mac.Sum(nil)
		for index2 := 0; index2 < 64; index2++ {
			firstHash[index2] = firstHash[index2] ^ tempHash[index2]
		}
	}
	return firstHash
}

func getKeyFromUserNameAndPassword(username string, password string) ([]byte, error) {
	username = strings.ToUpper(username)
	password = strings.ToUpper(password)
	extendString := func(str string) []byte {
		ret := make([]byte, len(str)*2)
		for index, char := range []byte(str) {
			ret[index*2] = 0
			ret[index*2+1] = char
		}
		return ret
	}
	buffer := append(extendString(username), extendString(password)...)
	if len(buffer)%8 > 0 {
		buffer = append(buffer, make([]byte, 8-len(buffer)%8)...)
	}
	key := []byte{1, 35, 69, 103, 137, 171, 205, 239}

	DesEnc := func(input []byte, key []byte) ([]byte, error) {
		ret := make([]byte, 8)
		enc, err := des.NewCipher(key)
		if err != nil {
			return nil, err
		}
		for x := 0; x < len(input)/8; x++ {
			for y := 0; y < 8; y++ {
				ret[y] = uint8(int(ret[y]) ^ int(input[x*8+y]))
			}
			output := make([]byte, 8)
			enc.Encrypt(output, ret)
			copy(ret, output)
		}
		return ret, nil
	}
	key1, err := DesEnc(buffer, key)
	if err != nil {
		return nil, err
	}
	key2, err := DesEnc(buffer, key1)
	if err != nil {
		return nil, err
	}
	// function OSLogonHelper.Method1_bytearray (DecryptSessionKey)
	return append(key2, make([]byte, 8)...), nil
}

// decrypt session key that come from the server
func decryptSessionKey(padding bool, encKey []byte, sessionKey string) ([]byte, error) {
	result, err := hex.DecodeString(sessionKey)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	//if padding {
	//	result = PKCS5Padding(result, blk.BlockSize())
	//}
	enc := cipher.NewCBCDecrypter(blk, make([]byte, 16))
	output := make([]byte, len(result))
	enc.CryptBlocks(output, result)
	cutLen := 0
	if padding {
		num := int(output[len(output)-1])
		if num < enc.BlockSize() {
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
		}
	}
	return output[:len(output)-cutLen], nil
}

// encrypt session key that generated from the client
func encryptSessionKey(padding bool, encKey []byte, sessionKey []byte) (string, error) {
	blk, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	enc := cipher.NewCBCEncrypter(blk, make([]byte, 16))
	originalLen := len(sessionKey)
	sessionKey = security.PKCS5Padding(sessionKey, blk.BlockSize())
	//if padding {
	//
	//}
	output := make([]byte, len(sessionKey))
	enc.CryptBlocks(output, sessionKey)
	if !padding {
		return fmt.Sprintf("%X", output[:originalLen]), nil
	}
	return fmt.Sprintf("%X", output), nil

	//cryptoServiceProvider.Mode = CipherMode.CBC;
	//cryptoServiceProvider.KeySize = key.Length * 8;
	//cryptoServiceProvider.BlockSize = O5LogonHelper.d;
	//cryptoServiceProvider.Key = key;
	//cryptoServiceProvider.IV = O5LogonHelper.f;
	//numArray = cryptoServiceProvider.CreateEncryptor().TransformFinalBlock(buffer, 0, buffer.Length);
}

// encrypt user password
func encryptPassword(password, key []byte, padding bool) (string, error) {
	buff1 := make([]byte, 0x10)
	_, err := rand.Read(buff1)
	if err != nil {
		return "", nil
	}
	buffer := append(buff1, password...)
	return encryptSessionKey(padding, key, buffer)
}

// generate encryption key for the password this depends on database verifier type
func (obj *AuthObject) generatePasswordEncKey() ([]byte, error) {
	hash := md5.New()
	key1 := obj.ServerSessKey
	key2 := obj.ClientSessKey
	start := 16

	logonCompatibility := obj.tcpNego.ServerCompileTimeCaps[4]
	if logonCompatibility&32 != 0 {
		var keyBuffer string
		var retKeyLen int
		switch obj.VerifierType {
		case 2361:
			buffer := append(key2[:len(key2)/2], key1[:len(key1)/2]...)
			keyBuffer = fmt.Sprintf("%X", buffer)
			retKeyLen = 16
		case 6949:
			buffer := append(key2[:24], key1[:24]...)
			keyBuffer = fmt.Sprintf("%X", buffer)
			retKeyLen = 24
		case 18453:
			buffer := append(key2, key1...)
			keyBuffer = fmt.Sprintf("%X", buffer)
			retKeyLen = 32
		default:
			return nil, errors.New("unsupported verifier type")
		}
		df2key, err := hex.DecodeString(obj.pbkdf2ChkSalt)
		if err != nil {
			return nil, err
		}
		return generateSpeedyKey(df2key, []byte(keyBuffer), obj.pbkdf2SderCount)[:retKeyLen], nil
	} else {
		switch obj.VerifierType {
		case 2361:
			buffer := make([]byte, 16)
			for x := 0; x < 16; x++ {
				buffer[x] = key1[x+start] ^ key2[x+start]
			}
			_, err := hash.Write(buffer)
			if err != nil {
				return nil, err
			}
			return hash.Sum(nil), nil
		case 6949:
			buffer := make([]byte, 24)
			for x := 0; x < 24; x++ {
				buffer[x] = key1[x+start] ^ key2[x+start]
			}
			_, err := hash.Write(buffer[:16])
			if err != nil {
				return nil, err
			}
			ret := hash.Sum(nil)
			hash.Reset()
			_, err = hash.Write(buffer[16:])
			if err != nil {
				return nil, err
			}
			ret = append(ret, hash.Sum(nil)...)
			return ret[:24], nil
		default:
			return nil, errors.New("unsupported verifier type")
		}

	}
}

//func (obj *AuthObject) VerifyResponse(response string) bool {
//	key, err := decryptSessionKey(true, obj.KeyHash, response)
//	if err != nil {
//		fmt.Println(err)
//		return false
//	}
//	//fmt.Printf("%#v\n", key)
//	return bytes.Compare(key[16:], []byte{83, 69, 82, 86, 69, 82, 95, 84, 79, 95, 67, 76, 73, 69, 78, 84}) == 0
//	//KZSR_SVR_RESPONSE = new byte[16]{ (byte) 83, (byte) 69, (byte) 82, (byte) 86, (byte) 69, (byte) 82, (byte) 95, (byte) 84, (byte) 79,
//	//(byte) 95, (byte) 67, (byte) 76, (byte) 73, (byte) 69, (byte) 78, (byte) 84 };
//
//}

//func (obj *AuthObject) TestResponse(password, pbkdf2ChkSalt string, vGenCount, sDerCount int) error {
//	padding := false
//	obj.pbkdf2ChkSalt = pbkdf2ChkSalt
//	obj.pbkdf2VgenCount = vGenCount
//	obj.pbkdf2SderCount = sDerCount
//	obj.tcpNego = &TCPNego{
//		MessageCode:           0,
//		ProtocolServerVersion: 0,
//		ProtocolServerString:  "",
//		OracleVersion:         0,
//		ServerCharset:         0,
//		ServerFlags:           0,
//		CharsetElem:           0,
//		ServernCharset:        0,
//		ServerCompileTimeCaps: []byte{0, 0, 0, 0, 32},
//		ServerRuntimeCaps:     nil,
//	}
//	salt, err := hex.DecodeString(obj.Salt)
//	if err != nil {
//		return err
//	}
//	message := append(salt, []byte("AUTH_PBKDF2_SPEEDY_KEY")...)
//	speedyKey := generateSpeedyKey(message, []byte(password), obj.pbkdf2VgenCount)
//
//	buffer := append(speedyKey, salt...)
//	hash := sha512.New()
//	hash.Write(buffer)
//	key := hash.Sum(nil)[:32]
//	obj.ServerSessKey, err = decryptSessionKey(padding, key, obj.EServerSessKey)
//	if err != nil {
//		return err
//	}
//	obj.ClientSessKey, err = decryptSessionKey(padding, key, obj.EClientSessKey)
//	if err != nil {
//		return err
//	}
//	newKey, err := obj.generatePasswordEncKey()
//	if err != nil {
//		return err
//	}
//	fmt.Println(decryptSessionKey(padding, newKey, obj.EPassword))
//
//	obj.EPassword, err = encryptPassword([]byte(password), newKey, false)
//	if err != nil {
//		return err
//	}
//	obj.ESpeedyKey, err = encryptPassword(speedyKey, newKey, false)
//	return err
//}
