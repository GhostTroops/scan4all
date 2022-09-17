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
	Normal AuthType = 0
	OS     AuthType = 1
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
				Timeout:               time.Duration(15),
				TransportDataUnitSize: 0xFFFF,
				SessionDataUnitSize:   0xFFFF,
				Protocol:              "tcp",
				SSL:                   false,
				SSLVerify:             true,
			},
			DatabaseInfo: network.DatabaseInfo{
				Servers: make([]network.ServerAddr, 0, 3),
			},
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
	if q != nil {
		for key, val := range q {
			switch strings.ToUpper(key) {
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
			case "AUTH TYPE":
				if strings.ToUpper(val[0]) == "OS" {
					ret.authType = OS
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
			case "OS PASSWORD HASH":
				ret.connOption.ClientInfo.Password = val[0]
				SetNTSAuth(&advanced_nego.NTSAuthHash{})
			case "DOMAIN":
				ret.connOption.DomainName = val[0]
			case "AUTH SERV":
				for _, tempVal := range val {
					ret.connOption.AuthService, _ = uniqueAppendString(ret.connOption.AuthService, strings.ToUpper(strings.TrimSpace(tempVal)), false)
				}
			case "SSL":
				ret.connOption.SSL = strings.ToUpper(val[0]) == "TRUE" || strings.ToUpper(val[0]) == "ENABLE"
			case "SSL VERIFY":
				ret.connOption.SSLVerify = strings.ToUpper(val[0]) == "TRUE" || strings.ToUpper(val[0]) == "ENABLE"
			case "DBA PRIVILEGE":
				ret.DBAPrivilege = DBAPrivilegeFromString(val[0])
			case "CONNECT TIMEOUT":
				fallthrough
			case "CONNECTION TIMEOUT":
				to, err := strconv.Atoi(val[0])
				if err != nil {
					return nil, errors.New("CONNECTION TIMEOUT value must be an integer")
				}
				ret.connOption.SessionInfo.Timeout = time.Duration(to)
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
	}
	if len(ret.connOption.Servers) == 0 {
		return nil, errors.New("empty connection servers")
	}
	if len(ret.WalletPath) > 0 && len(ret.connOption.UserID) > 0 {
		if len(ret.connOption.ServiceName) == 0 {
			return nil, errors.New("you should specify server/service if you will use wallet")
		}
		ret.w, err = NewWallet(path.Join(ret.WalletPath, "cwallet.sso"))
		if err != nil {
			return nil, err
		}
		if len(ret.password) == 0 {
			serv := ret.connOption.Servers[0]
			cred, err := ret.w.getCredential(serv.Addr, serv.Port, ret.connOption.ServiceName, ret.connOption.UserID)
			if err != nil {
				return nil, err
			}
			if cred == nil {
				return nil, errors.New(
					fmt.Sprintf("cannot find credentials for server: %s, service: %s,  username: %s",
						serv, ret.connOption.ServiceName, ret.connOption.UserID))
			}
			ret.connOption.UserID = cred.username
			ret.password = cred.password
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
	if len(connStr.connOption.UserID) == 0 || len(connStr.password) == 0 {
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
	var temp *user.User
	if userName := os.Getenv("USER"); len(userName) > 0 {
		temp = &user.User{
			Uid:      "",
			Gid:      "",
			Username: userName,
			Name:     userName,
			HomeDir:  "",
		}
	} else {
		temp, _ = user.Current()
	}
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
