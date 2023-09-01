package go_ora

import (
	"errors"
	"fmt"
	"github.com/sijms/go-ora/v2/advanced_nego"
	"github.com/sijms/go-ora/v2/network"
	"github.com/sijms/go-ora/v2/trace"
	"net"
	"net/url"
	"os"
	"os/user"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type PromotableTransaction int

//const (
//	Promotable PromotableTransaction = 1
//	Local      PromotableTransaction = 0
//)

type DBAPrivilege int

const (
	NONE    DBAPrivilege = 0
	SYSDBA  DBAPrivilege = 0x20
	SYSOPER DBAPrivilege = 0x40
)

type AuthType int

const (
	Normal   AuthType = 0
	OS       AuthType = 1
	Kerberos AuthType = 2
	TCPS     AuthType = 3
)
const defaultPort int = 1521

func DBAPrivilegeFromString(s string) DBAPrivilege {
	S := strings.ToUpper(s)
	if S == "SYSDBA" {
		return SYSDBA
	} else if S == "SYSOPER" {
		return SYSOPER
	} else {
		return NONE
	}
}

func getCharsetID(charset string) (int, error) {
	charsetMap := map[string]int{
		"US7ASCII":         0x1,
		"WE8DEC":           0x2,
		"WE8HP":            0x3,
		"US8PC437":         0x4,
		"WE8EBCDIC37":      0x5,
		"WE8EBCDIC500":     0x6,
		"WE8EBCDIC1140":    0x7,
		"WE8EBCDIC285":     0x8,
		"WE8EBCDIC1146":    0x9,
		"WE8PC850":         0xA,
		"D7DEC":            0xB,
		"F7DEC":            0xC,
		"S7DEC":            0xD,
		"E7DEC":            0xE,
		"SF7ASCII":         0xF,
		"NDK7DEC":          0x10,
		"I7DEC":            0x11,
		"NL7DEC":           0x12,
		"CH7DEC":           0x13,
		"YUG7ASCII":        0x14,
		"SF7DEC":           0x15,
		"TR7DEC":           0x16,
		"IW7IS960":         0x17,
		"IN8ISCII":         0x19,
		"WE8EBCDIC1148":    0x1b,
		"WE8PC858":         0x1c,
		"WE8ISO8859P1":     0x1f,
		"EE8ISO8859P2":     0x20,
		"SE8ISO8859P3":     0x21,
		"NEE8ISO8859P4":    0x22,
		"CL8ISO8859P5":     0x23,
		"AR8ISO8859P6":     0x24,
		"EL8ISO8859P7":     0x25,
		"IW8ISO8859P8":     0x26,
		"WE8ISO8859P9":     0x27,
		"NE8ISO8859P10":    0x28,
		"TH8TISASCII":      0x29,
		"TH8TISEBCDIC":     0x2a,
		"BN8BSCII":         0x2b,
		"VN8VN3":           0x2c,
		"VN8MSWIN1258":     0x2d,
		"WE8ISO8859P15":    0x2e,
		"BLT8ISO8859P13":   0x2f,
		"CEL8ISO8859P14":   0x30,
		"CL8ISOIR111":      0x31,
		"WE8NEXTSTEP":      0x32,
		"CL8KOI8U":         0x33,
		"AZ8ISO8859P9E":    0x34,
		"AR8ASMO708PLUS":   0x3d,
		"AR8EBCDICX":       0x46,
		"AR8XBASIC":        0x48,
		"EL8DEC":           0x51,
		"TR8DEC":           0x52,
		"WE8EBCDIC37C":     0x5a,
		"WE8EBCDIC500C":    0x5b,
		"IW8EBCDIC424":     0x5c,
		"TR8EBCDIC1026":    0x5d,
		"WE8EBCDIC871":     0x5e,
		"WE8EBCDIC284":     0x5f,
		"WE8EBCDIC1047":    0x60,
		"WE8EBCDIC1140C":   0x61,
		"WE8EBCDIC1145":    0x62,
		"WE8EBCDIC1148C":   0x63,
		"WE8EBCDIC1047E":   0x64,
		"WE8EBCDIC924":     0x65,
		"EEC8EUROASCI":     0x6e,
		"EEC8EUROPA3":      0x71,
		"LA8PASSPORT":      0x72,
		"BG8PC437S":        0x8c,
		"EE8PC852":         0x96,
		"RU8PC866":         0x98,
		"RU8BESTA":         0x99,
		"IW8PC1507":        0x9a,
		"RU8PC855":         0x9b,
		"TR8PC857":         0x9c,
		"CL8MACCYRILLIC":   0x9e,
		"CL8MACCYRILLICS":  0x9f,
		"WE8PC860":         0xa0,
		"IS8PC861":         0xa1,
		"EE8MACCES":        0xa2,
		"EE8MACCROATIANS":  0xa3,
		"TR8MACTURKISHS":   0xa4,
		"IS8MACICELANDICS": 0xa5,
		"EL8MACGREEKS":     0xa6,
		"IW8MACHEBREWS":    0xa7,
		"EE8MSWIN1250":     0xaa,
		"CL8MSWIN1251":     0xab,
		"ET8MSWIN923":      0xac,
		"BG8MSWIN":         0xad,
		"EL8MSWIN1253":     0xae,
		"IW8MSWIN1255":     0xaf,
		"LT8MSWIN921":      0xb0,
		"TR8MSWIN1254":     0xb1,
		"WE8MSWIN1252":     0xb2,
		"BLT8MSWIN1257":    0xb3,
		"D8EBCDIC273":      0xb4,
		"I8EBCDIC280":      0xb5,
		"DK8EBCDIC277":     0xb6,
		"S8EBCDIC278":      0xb7,
		"EE8EBCDIC870":     0xb8,
		"CL8EBCDIC1025":    0xb9,
		"F8EBCDIC297":      0xba,
		"IW8EBCDIC1086":    0xbb,
		"CL8EBCDIC1025X":   0xbc,
		"D8EBCDIC1141":     0xbd,
		"N8PC865":          0xbe,
		"BLT8CP921":        0xbf,
		"LV8PC1117":        0xc0,
		"LV8PC8LR":         0xc1,
		"BLT8EBCDIC1112":   0xc2,
		"LV8RST104090":     0xc3,
		"CL8KOI8R":         0xc4,
		"BLT8PC775":        0xc5,
		"DK8EBCDIC1142":    0xc6,
		"S8EBCDIC1143":     0xc7,
		"I8EBCDIC1144":     0xc8,
		"F7SIEMENS9780X":   0xc9,
		"E7SIEMENS9780X":   0xca,
		"S7SIEMENS9780X":   0xcb,
		"DK7SIEMENS9780X":  0xcc,
		"N7SIEMENS9780X":   0xcd,
		"I7SIEMENS9780X":   0xce,
		"D7SIEMENS9780X":   0xcf,
		"F8EBCDIC1147":     0xd0,
		"WE8GCOS7":         0xd2,
		"EL8GCOS7":         0xd3,
		"US8BS2000":        0xdd,
		"D8BS2000":         0xde,
		"F8BS2000":         0xdf,
		"E8BS2000":         0xe0,
		"DK8BS2000":        0xe1,
		"S8BS2000":         0xe2,
		"WE8BS2000E":       0xe6,
		"WE8BS2000":        0xe7,
		"EE8BS2000":        0xe8,
		"CE8BS2000":        0xe9,
		"CL8BS2000":        0xeb,
		"WE8BS2000L5":      0xef,
		"WE8DG":            0xf1,
		"WE8NCR4970":       0xfb,
		"WE8ROMAN8":        0x105,
		"EE8MACCE":         0x106,
		"EE8MACCROATIAN":   0x107,
		"TR8MACTURKISH":    0x108,
		"IS8MACICELANDIC":  0x109,
		"EL8MACGREEK":      0x10a,
		"IW8MACHEBREW":     0x10b,
		"US8ICL":           0x115,
		"WE8ICL":           0x116,
		"WE8ISOICLUK":      0x117,
		"EE8EBCDIC870C":    0x12d,
		"EL8EBCDIC875S":    0x137,
		"TR8EBCDIC1026S":   0x138,
		"BLT8EBCDIC1112S":  0x13a,
		"IW8EBCDIC424S":    0x13b,
		"EE8EBCDIC870S":    0x13c,
		"CL8EBCDIC1025S":   0x13d,
		"TH8TISEBCDICS":    0x13f,
		"AR8EBCDIC420S":    0x140,
		"CL8EBCDIC1025C":   0x142,
		"CL8EBCDIC1025R":   0x143,
		"EL8EBCDIC875R":    0x144,
		"CL8EBCDIC1158":    0x145,
		"CL8EBCDIC1158R":   0x146,
		"EL8EBCDIC423R":    0x147,
		"WE8MACROMAN8":     0x15f,
		"WE8MACROMAN8S":    0x160,
		"TH8MACTHAI":       0x161,
		"TH8MACTHAIS":      0x162,
		"HU8CWI2":          0x170,
		"EL8PC437S":        0x17c,
		"EL8EBCDIC875":     0x17d,
		"EL8PC737":         0x17e,
		"LT8PC772":         0x17f,
		"LT8PC774":         0x180,
		"EL8PC869":         0x181,
		"EL8PC851":         0x182,
		"CDN8PC863":        0x186,
		"HU8ABMOD":         0x191,
		"AR8ASMO8X":        0x1f4,
		"AR8NAFITHA711T":   0x1f8,
		"AR8SAKHR707T":     0x1f9,
		"AR8MUSSAD768T":    0x1fa,
		"AR8ADOS710T":      0x1fb,
		"AR8ADOS720T":      0x1fc,
		"AR8APTEC715T":     0x1fd,
		"AR8NAFITHA721T":   0x1ff,
		"AR8HPARABIC8T":    0x202,
		"AR8NAFITHA711":    0x22a,
		"AR8SAKHR707":      0x22b,
		"AR8MUSSAD768":     0x22c,
		"AR8ADOS710":       0x22d,
		"AR8ADOS720":       0x22e,
		"AR8APTEC715":      0x22F,
		"AR8MSWIN1256":     0x230,
		"AR8NAFITHA721":    0x231,
		"AR8SAKHR706":      0x233,
		"AR8ARABICMAC":     0x235,
		"AR8ARABICMACS":    0x236,
		"AR8ARABICMACT":    0x237,
		"LA8ISO6937":       0x24E,
		"JA16VMS":          0x33D,
		"JA16EUC":          0x33E,
		"JA16EUCYEN":       0x33F,
		"JA16SJIS":         0x340,
		//"JA16DBCS" : 833,
		//"JA16SJISYEN" : 834,
		//"JA16EBCDIC930" : 835,
		//"JA16MACSJIS" : 836,
		//"JA16EUCTILDE" : 837,
		//"JA16SJISTILDE" : 838,
		//"KO16KSC5601" : 840,
		//"KO16DBCS" : 842,
		//"KO16KSCCS" : 845,
		//"KO16MSWIN949" : 846,
		"ZHS16CGB231280":    0x352,
		"ZHS16MACCGB231280": 0x353,
		"ZHS16GBK":          0x354,
		//"ZHS16DBCS" : 853,
		//"ZHS32GB18030" : 854,
		//"ZHT32EUC" : 860,
		//"ZHT32SOPS" : 861,
		"ZHT16DBT": 0x35E,
		//"ZHT32TRIS" : 863,
		//"ZHT16DBCS" : 864,
		//"ZHT16BIG5" : 865,
		//"ZHT16CCDC" : 866,
		//"ZHT16MSWIN950" : 867,
		//"ZHT16HKSCS" : 868,
		"AL24UTFFSS": 0x366,
		"UTF8":       0x367,
		"UTFE":       0x368,
		"AL32UTF8":   0x369,
		//"ZHT16HKSCS31" : 992,
		//"JA16EUCFIXED" : 1830,
		//"JA16SJISFIXED" : 1832,
		//"JA16DBCSFIXED" : 1833,
		//"KO16KSC5601FIXED" : 1840,
		//"KO16DBCSFIXED" : 1842,
		//"ZHS16CGB231280FIXED" : 1850,
		//"ZHS16GBKFIXED" : 1852,
		//"ZHS16DBCSFIXED" : 1853,
		//"ZHT32EUCFIXED" : 1860,
		//"ZHT32TRISFIXED" : 1863,
		//"ZHT16DBCSFIXED" : 1864,
		//"ZHT16BIG5FIXED" : 1865,
		"AL16UTF16": 0x7D0,
	}
	id, found := charsetMap[strings.ToUpper(charset)]
	if !found {
		return 0, fmt.Errorf("charset %s is not supported by the driver", charset)
	}
	return id, nil
}

//type EnList int

//const (
//	FALSE   EnList = 0
//	TRUE    EnList = 1
//	DYNAMIC EnList = 2
//)

//func EnListFromString(s string) EnList {
//	S := strings.ToUpper(s)
//	if S == "TRUE" {
//		return TRUE
//	} else if S == "DYNAMIC" {
//		return DYNAMIC
//	} else {
//		return FALSE
//	}
//}

type ConnectionString struct {
	connOption   network.ConnectionOption
	DataSource   string
	Host         string
	Port         int
	DBAPrivilege DBAPrivilege
	password     string
	Trace        string // Trace file
	WalletPath   string
	walletPass   string
	w            *wallet
	authType     AuthType
	//EnList             EnList
	//ConnectionLifeTime int
	//IncrPoolSize       int
	//DecrPoolSize       int
	//MaxPoolSize        int
	//MinPoolSize        int

	//PasswordSecurityInfo  bool
	//Pooling               bool

	//PromotableTransaction PromotableTransaction
	//ProxyUserID           string
	//ProxyPassword         string
	//ValidateConnection    bool
	//StmtCacheSize         int
	//StmtCachePurge        bool
	//HaEvent               bool
	//LoadBalance           bool
	//MetadataBooling       bool
	//ContextConnection     bool
	//SelfTuning            bool
	//ApplicationEdition    string
	//PoolRegulator         int
	//ConnectionPoolTimeout int

}

// BuildJDBC create url from user, password and JDBC description string
func BuildJDBC(user, password, connStr string, options map[string]string) string {
	if options == nil {
		options = make(map[string]string)
	}
	options["connStr"] = connStr
	return BuildUrl("", 0, "", user, password, options)
}

// BuildUrl create databaseURL from server, port, service, user, password, urlOptions
// this function help build a will formed databaseURL and accept any character as it
// convert special charters to corresponding values in URL
func BuildUrl(server string, port int, service, user, password string, options map[string]string) string {
	ret := fmt.Sprintf("oracle://%s:%s@%s/%s", url.PathEscape(user), url.PathEscape(password),
		net.JoinHostPort(server, strconv.Itoa(port)), url.PathEscape(service))
	if options != nil {
		ret += "?"
		for key, val := range options {
			val = strings.TrimSpace(val)
			for _, temp := range strings.Split(val, ",") {
				temp = strings.TrimSpace(temp)
				if strings.ToUpper(key) == "SERVER" {
					ret += fmt.Sprintf("%s=%s&", key, temp)
				} else {
					ret += fmt.Sprintf("%s=%s&", key, url.QueryEscape(temp))
				}
			}
		}
		ret = strings.TrimRight(ret, "&")
	}
	return ret
}

// newConnectionStringFromUrl create new connection string from databaseURL data and options
func newConnectionStringFromUrl(databaseUrl string) (*ConnectionString, error) {
	u, err := url.Parse(databaseUrl)

	if err != nil {
		return nil, err
	}
	q := u.Query()
	//p := u.Port()
	ret := &ConnectionString{
		connOption: network.ConnectionOption{
			PrefetchRows: 25,
			SessionInfo: network.SessionInfo{
				Timeout: time.Second * time.Duration(120),
				//TransportDataUnitSize: 0xFFFF,
				//SessionDataUnitSize:   0xFFFF,
				TransportDataUnitSize: 0x200000,
				SessionDataUnitSize:   0x200000,
				Protocol:              "tcp",
				SSL:                   false,
				SSLVerify:             true,
			},
			DatabaseInfo: network.DatabaseInfo{
				Servers: make([]network.ServerAddr, 0, 3),
			},
			ClientInfo: network.ClientInfo{Territory: "AMERICA", Language: "AMERICAN"},
		},
		Port:         defaultPort,
		DBAPrivilege: NONE,
		//EnList:                TRUE,
		//IncrPoolSize:          5,
		//DecrPoolSize:          5,
		//MaxPoolSize:           100,
		//MinPoolSize:           1,
		//PromotableTransaction: Promotable,
		//StmtCacheSize:         20,
		//MetadataBooling:       true,
		//SelfTuning:            true,
		//PoolRegulator:         100,
		//ConnectionPoolTimeout: 15,
	}
	ret.connOption.UserID = u.User.Username()
	ret.password, _ = u.User.Password()
	if strings.ToUpper(ret.connOption.UserID) == "SYS" {
		ret.DBAPrivilege = SYSDBA
	}

	host, p, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, err
	}
	if len(host) > 0 {
		tempAddr := network.ServerAddr{Addr: host, Port: defaultPort}
		tempAddr.Port, err = strconv.Atoi(p)
		if err != nil {
			tempAddr.Port = defaultPort
		}
		ret.connOption.Servers = append(ret.connOption.Servers, tempAddr)
	}
	ret.connOption.ServiceName = strings.Trim(u.Path, "/")
	for key, val := range q {
		switch strings.ToUpper(key) {
		case "CID":
			ret.connOption.Cid = val[0]
		case "CONNSTR":
			err = ret.connOption.UpdateDatabaseInfo(q.Get("connStr"))
			if err != nil {
				return nil, err
			}
		case "SERVER":
			for _, srv := range val {
				srv = strings.TrimSpace(srv)
				if srv != "" {
					host, p, err := net.SplitHostPort(srv)
					if err != nil {
						return nil, err
					}
					tempAddr := network.ServerAddr{Addr: host, Port: defaultPort}
					if p != "" {
						tempAddr.Port, err = strconv.Atoi(p)
						if err != nil {
							tempAddr.Port = defaultPort
						}
					}
					ret.connOption.Servers = append(ret.connOption.Servers, tempAddr)
				}
			}
		case "SERVICE NAME":
			ret.connOption.ServiceName = val[0]
		case "SID":
			ret.connOption.SID = val[0]
		case "INSTANCE NAME":
			ret.connOption.InstanceName = val[0]
		case "WALLET":
			ret.WalletPath = val[0]
		case "WALLET PASSWORD":
			ret.walletPass = val[0]
		case "AUTH TYPE":
			if strings.ToUpper(val[0]) == "OS" {
				ret.authType = OS
			} else if strings.ToUpper(val[0]) == "KERBEROS" {
				ret.authType = Kerberos
			} else if strings.ToUpper(val[0]) == "TCPS" {
				ret.authType = TCPS
			} else {
				ret.authType = Normal
			}
		case "OS USER":
			ret.connOption.ClientInfo.UserName = val[0]
		case "OS PASS":
			fallthrough
		case "OS PASSWORD":
			ret.connOption.ClientInfo.Password = val[0]
		case "OS HASH":
			fallthrough
		case "OS PASSHASH":
			fallthrough
		case "OS PASSWORD HASH":
			ret.connOption.ClientInfo.Password = val[0]
			SetNTSAuth(&advanced_nego.NTSAuthHash{})
		case "DOMAIN":
			ret.connOption.DomainName = val[0]
		case "AUTH SERV":
			for _, tempVal := range val {
				ret.connOption.AuthService, _ = uniqueAppendString(ret.connOption.AuthService, strings.ToUpper(strings.TrimSpace(tempVal)), false)
			}
		case "ENCRYPTION":
			switch strings.ToUpper(val[0]) {
			case "ACCEPTED":
				ret.connOption.EncServiceLevel = 0
			case "REJECTED":
				ret.connOption.EncServiceLevel = 1
			case "REQUESTED":
				ret.connOption.EncServiceLevel = 2
			case "REQUIRED":
				ret.connOption.EncServiceLevel = 3
			default:
				return nil, fmt.Errorf("unknown encryption service level: %s use one of the following [ACCEPTED, REJECTED, REQUESTED, REQUIRED]", val[0])
			}
		case "DATA INTEGRITY":
			switch strings.ToUpper(val[0]) {
			case "ACCEPTED":
				ret.connOption.IntServiceLevel = 0
			case "REJECTED":
				ret.connOption.IntServiceLevel = 1
			case "REQUESTED":
				ret.connOption.IntServiceLevel = 2
			case "REQUIRED":
				ret.connOption.IntServiceLevel = 3
			default:
				return nil, fmt.Errorf("unknown data integrity service level: %s use one of the following [ACCEPTED, REJECTED, REQUESTED, REQUIRED]", val[0])
			}
		case "SSL":
			ret.connOption.SSL = strings.ToUpper(val[0]) == "TRUE" ||
				strings.ToUpper(val[0]) == "ENABLE" ||
				strings.ToUpper(val[0]) == "ENABLED"
		case "SSL VERIFY":
			ret.connOption.SSLVerify = strings.ToUpper(val[0]) == "TRUE" ||
				strings.ToUpper(val[0]) == "ENABLE" ||
				strings.ToUpper(val[0]) == "ENABLED"
		case "DBA PRIVILEGE":
			ret.DBAPrivilege = DBAPrivilegeFromString(val[0])
		case "TIMEOUT":
			fallthrough
		case "CONNECT TIMEOUT":
			fallthrough
		case "CONNECTION TIMEOUT":
			to, err := strconv.Atoi(val[0])
			if err != nil {
				return nil, errors.New("CONNECTION TIMEOUT value must be an integer")
			}
			ret.connOption.SessionInfo.Timeout = time.Second * time.Duration(to)
		case "TRACE FILE":
			ret.Trace = val[0]
		case "PREFETCH_ROWS":
			ret.connOption.PrefetchRows, err = strconv.Atoi(val[0])
			if err != nil {
				ret.connOption.PrefetchRows = 25
			}
		case "UNIX SOCKET":
			ret.connOption.SessionInfo.UnixAddress = val[0]
		case "PROXY CLIENT NAME":
			ret.connOption.DatabaseInfo.ProxyClientName = val[0]
		case "FAILOVER":
			return nil, errors.New("starting from v2.7.0 this feature (FAILOVER) is not supported and the driver use database/sql package fail over")
			//ret.connOption.Failover, err = strconv.Atoi(val[0])
			//if err != nil {
			//	ret.connOption.Failover = 0
			//}
		case "RETRYTIME":
			fallthrough
		case "RE-TRY TIME":
			fallthrough
		case "RETRY TIME":
			return nil, errors.New("starting from v2.7.0 this feature (RETRY TIME) is not supported and the driver use database/sql package fail over")
			//ret.connOption.RetryTime, err = strconv.Atoi(val[0])
			//if err != nil {
			//	ret.connOption.RetryTime = 0
			//}
		case "LOB FETCH":
			tempVal := strings.ToUpper(val[0])
			if tempVal == "PRE" {
				ret.connOption.Lob = 0
			} else if tempVal == "POST" {
				ret.connOption.Lob = 1
			} else {
				return nil, errors.New("LOB FETCH value should be: PRE(default) or POST")
			}
		case "LANGUAGE":
			ret.connOption.Language = val[0]
		case "TERRITORY":
			ret.connOption.Territory = val[0]
		case "CHARSET":
			fallthrough
		case "CLIENT CHARSET":
			ret.connOption.CharsetID, err = getCharsetID(val[0])
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unknown URL option: %s", key)
			//else if tempVal == "IMPLICIT" || tempVal == "AUTO" {
			//	ret.connOption.Lob = 1
			//} else if tempVal == "EXPLICIT" || tempVal == "MANUAL" {
			//	ret.connOption.Lob = 2
			//} else {
			//	return nil, errors.New("LOB value should be: Prefetch, Implicit(AUTO) or Explicit(manual)")
			//}
			//case "ENLIST":
			//	ret.EnList = EnListFromString(val[0])
			//case "INC POOL SIZE":
			//	ret.IncrPoolSize, err = strconv.Atoi(val[0])
			//	if err != nil {
			//		return nil, errors.New("INC POOL SIZE value must be an integer")
			//	}
			//case "DECR POOL SIZE":
			//	ret.DecrPoolSize, err = strconv.Atoi(val[0])
			//	if err != nil {
			//		return nil, errors.New("DECR POOL SIZE value must be an integer")
			//	}
			//case "MAX POOL SIZE":
			//	ret.MaxPoolSize, err = strconv.Atoi(val[0])
			//	if err != nil {
			//		return nil, errors.New("MAX POOL SIZE value must be an integer")
			//	}
			//case "MIN POOL SIZE":
			//	ret.MinPoolSize, err = strconv.Atoi(val[0])
			//	if err != nil {
			//		return nil, errors.New("MIN POOL SIZE value must be an integer")
			//	}
			//case "POOL REGULATOR":
			//	ret.PoolRegulator, err = strconv.Atoi(val[0])
			//	if err != nil {
			//		return nil, errors.New("POOL REGULATOR value must be an integer")
			//	}
			//case "STATEMENT CACHE SIZE":
			//	ret.StmtCacheSize, err = strconv.Atoi(val[0])
			//	if err != nil {
			//		return nil, errors.New("STATEMENT CACHE SIZE value must be an integer")
			//	}
			//case "CONNECTION POOL TIMEOUT":
			//	ret.ConnectionPoolTimeout, err = strconv.Atoi(val[0])
			//	if err != nil {
			//		return nil, errors.New("CONNECTION POOL TIMEOUT value must be an integer")
			//	}
			//case "CONNECTION LIFETIME":
			//	ret.ConnectionLifeTime, err = strconv.Atoi(val[0])
			//	if err != nil {
			//		return nil, errors.New("CONNECTION LIFETIME value must be an integer")
			//	}
			//case "PERSIST SECURITY INFO":
			//	ret.PasswordSecurityInfo = val[0] == "TRUE"
			//case "POOLING":
			//	ret.Pooling = val[0] == "TRUE"
			//case "VALIDATE CONNECTION":
			//	ret.ValidateConnection = val[0] == "TRUE"
			//case "STATEMENT CACHE PURGE":
			//	ret.StmtCachePurge = val[0] == "TRUE"
			//case "HA EVENTS":
			//	ret.HaEvent = val[0] == "TRUE"
			//case "LOAD BALANCING":
			//	ret.LoadBalance = val[0] == "TRUE"
			//case "METADATA POOLING":
			//	ret.MetadataBooling = val[0] == "TRUE"
			//case "SELF TUNING":
			//	ret.SelfTuning = val[0] == "TRUE"
			//case "CONTEXT CONNECTION":
			//	ret.ContextConnection = val[0] == "TRUE"
			//case "PROMOTABLE TRANSACTION":
			//	if val[0] == "PROMOTABLE" {
			//		ret.PromotableTransaction = Promotable
			//	} else {
			//		ret.PromotableTransaction = Local
			//	}
			//case "APPLICATION EDITION":
			//	ret.ApplicationEdition = val[0]
			//case "PROXY USER ID":
			//	ret.ProxyUserID = val[0]
			//case "PROXY PASSWORD":
			//	ret.ProxyPassword = val[0]
		}
	}
	if len(ret.connOption.Servers) == 0 {
		return nil, errors.New("empty connection servers")
	}
	if len(ret.WalletPath) > 0 {
		if len(ret.connOption.ServiceName) == 0 {
			return nil, errors.New("you should specify server/service if you will use wallet")
		}
		if _, err = os.Stat(path.Join(ret.WalletPath, "ewallet.p12")); err == nil && len(ret.walletPass) > 0 {
			fileData, err := os.ReadFile(path.Join(ret.WalletPath, "ewallet.p12"))
			if err != nil {
				return nil, err
			}
			ret.w = &wallet{password: []byte(ret.walletPass)}
			err = ret.w.readPKCS12(fileData)
			if err != nil {
				return nil, err
			}
		} else {
			ret.w, err = NewWallet(path.Join(ret.WalletPath, "cwallet.sso"))
			if err != nil {
				return nil, err
			}
		}

		if len(ret.connOption.UserID) > 0 {
			if len(ret.password) == 0 {
				serv := ret.connOption.Servers[0]
				cred, err := ret.w.getCredential(serv.Addr, serv.Port, ret.connOption.ServiceName, ret.connOption.UserID)
				if err != nil {
					return nil, err
				}
				if cred == nil {
					return nil, errors.New(
						fmt.Sprintf("cannot find credentials for server: %s:%d, service: %s,  username: %s",
							serv.Addr, serv.Port, ret.connOption.ServiceName, ret.connOption.UserID))
				}
				ret.connOption.UserID = cred.username
				ret.password = cred.password
			}
		}
	}
	return ret, ret.validate()
}

// validate check is data in connection string is correct and fulfilled
func (connStr *ConnectionString) validate() error {
	//if !connStr.Pooling {
	//	connStr.MaxPoolSize = -1
	//	connStr.MinPoolSize = 0
	//	connStr.IncrPoolSize = -1
	//	connStr.DecrPoolSize = 0
	//	connStr.PoolRegulator = 0
	//}

	//if len(connStr.UserID) == 0 {
	//	return errors.New("empty user name")
	//}
	//if len(connStr.Password) == 0 {
	//	return errors.New("empty password")
	//}
	if len(connStr.connOption.SID) == 0 && len(connStr.connOption.ServiceName) == 0 {
		return errors.New("empty SID and service name")
	}
	if connStr.authType == Kerberos {
		connStr.connOption.AuthService = append(connStr.connOption.AuthService, "KERBEROS5")
	}
	if connStr.authType == TCPS {
		connStr.connOption.AuthService = append(connStr.connOption.AuthService, "TCPS")
	}
	if len(connStr.connOption.UserID) == 0 || len(connStr.password) == 0 && connStr.authType == Normal {
		connStr.authType = OS
	}
	if connStr.authType == OS {
		if runtime.GOOS == "windows" {
			connStr.connOption.AuthService = append(connStr.connOption.AuthService, "NTS")
		}
	}

	if connStr.connOption.SSL {
		connStr.connOption.Protocol = "tcps"
	}
	if len(connStr.Trace) > 0 {
		tf, err := os.Create(connStr.Trace)
		if err != nil {
			//noinspection GoErrorStringFormat
			return fmt.Errorf("Can't open trace file: %w", err)
		}
		connStr.connOption.Tracer = trace.NewTraceWriter(tf)
	} else {
		connStr.connOption.Tracer = trace.NilTracer()
	}

	// get client info
	var idx int
	var temp = getCurrentUser()

	if temp != nil {
		idx = strings.Index(temp.Username, "\\")
		if idx >= 0 {
			if len(connStr.connOption.DomainName) == 0 {
				connStr.connOption.DomainName = temp.Username[:idx]
			}
			if len(connStr.connOption.ClientInfo.UserName) == 0 {
				connStr.connOption.ClientInfo.UserName = temp.Username[idx+1:]
			}
		} else {
			if len(connStr.connOption.ClientInfo.UserName) == 0 {
				connStr.connOption.ClientInfo.UserName = temp.Username
			}
		}
	}
	connStr.connOption.HostName, _ = os.Hostname()
	idx = strings.LastIndex(os.Args[0], "/")
	idx++
	if idx < 0 {
		idx = 0
	}
	connStr.connOption.ProgramPath = os.Args[0]
	connStr.connOption.ProgramName = os.Args[0][idx:]
	connStr.connOption.DriverName = "OracleClientGo"
	connStr.connOption.PID = os.Getpid()
	return nil
}

func uniqueAppendString(list []string, newItem string, ignoreCase bool) ([]string, bool) {
	found := false
	for _, temp := range list {
		if ignoreCase {
			if strings.ToUpper(temp) == strings.ToUpper(newItem) {
				found = true
				break
			}
		} else {
			if temp == newItem {
				found = true
				break
			}
		}
	}
	if !found {
		list = append(list, newItem)
	}
	return list, !found
}

func getCurrentUser() *user.User {
	if userName := os.Getenv("USER"); len(userName) > 0 {
		return &user.User{
			Uid:      "",
			Gid:      "",
			Username: userName,
			Name:     userName,
			HomeDir:  "",
		}
	} else {
		temp, _ := user.Current()
		return temp
	}
}
