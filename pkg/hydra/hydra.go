package hydra

import (
	"github.com/GhostTroops/scan4all/pkg/hydra/oracle"
	"github.com/GhostTroops/scan4all/pkg/kscan/lib/gotelnet"
	"github.com/GhostTroops/scan4all/pkg/kscan/lib/misc"
	"github.com/GhostTroops/scan4all/pkg/kscan/lib/pool"
	"strings"
	"time"
)

type Cracker struct {
	Pool         *pool.Pool
	authList     *AuthList
	authInfo     *AuthInfo
	Out          chan AuthInfo
	onlyPassword bool
}

var (
	DefaultAuthMap map[string]*AuthList
	CustomAuthMap  *AuthList
	// rtsp://admin:admin@192.168.0.111:554/0x8b6c42
	// rtsp: 554, 5554,8554
	ProtocolList = strings.Split("rdp,ssh,rsh-spx,mysql,mssql,oracle,postgresql,redis,ftp,mongodb,mongod,smb,telnet,snmp,wap-wsp,router,winrm,pop3,socks5,vnc,pop3s", ",")
)

func NewCracker(info *AuthInfo, isAuthUpdate bool, threads int) *Cracker {
	c := &Cracker{}
	if info.Protocol == "redis" {
		c.onlyPassword = true
	} else {
		c.onlyPassword = false
	}

	c.Pool = pool.NewPool(threads)
	c.authInfo = info
	c.authList = func() *AuthList {
		list := DefaultAuthMap[c.authInfo.Protocol]
		if c.onlyPassword {
			CustomAuthMap.Username = []string{}
		}
		if isAuthUpdate {
			list.Merge(CustomAuthMap)
			return list
		}
		if CustomAuthMap.IsEmpty() == false {
			list.Replace(CustomAuthMap)
			return list
		}
		return list
	}()
	c.Out = make(chan AuthInfo)
	c.Pool.Interval = time.Microsecond * 13

	return c
}

func (c *Cracker) Run() {
	ip := c.authInfo.IPAddr
	port := c.authInfo.Port
	//开启输出监测
	go c.OutWatchDog()
	//选择暴力破解函数
	switch c.authInfo.Protocol {
	case "rdp":
		c.Pool.Function = rdpCracker(ip, port)
	case "mysql":
		c.Pool.Function = mysqlCracker
	case "pop3s":
		c.Pool.Function = pop3Cracker
	case "pop3":
		c.Pool.Function = pop3Cracker
	case "mssql":
		c.Pool.Function = mssqlCracker
	case "oracle":
		if oracle.CheckProtocol(ip, port) == false {
			c.Pool.OutDone()
			return
		}
		c.Pool.Function = oracleCracker(ip, port)
		//若SID未知，则不进行后续暴力破解
	case "postgresql":
		c.Pool.Function = postgresqlCracker
	case "socks5":
		c.Pool.Function = Socks5Cracker
	case "vnc":
		c.Pool.Function = VncCracker
	case "ldap", "rsh-spx", "ssh":
		c.Pool.Function = sshCracker
	case "telnet":
		serverType := getTelnetServerType(ip, port)
		if serverType == gotelnet.UnauthorizedAccess {
			c.authInfo.Auth.Password = ""
			c.authInfo.Auth.Username = ""
			c.authInfo.Auth.Other["Status"] = "UnauthorizedAccess"
			c.authInfo.Status = true
			c.Pool.Out <- *c.authInfo
			c.Pool.OutDone()
			return
		}
		c.Pool.Function = telnetCracker(serverType)
	case "ftp":
		c.Pool.Function = ftpCracker
	case "snmp":
		c.Pool.Function = snmpCracker
	case "wap-wsp": // Elasticsearch
		c.Pool.Function = elasticCracker
	//	PORT     STATE SERVICE REASON
	// 8728/tcp open  unknown syn-ack
	case "router": //
		c.Pool.Function = RouterOsCracker
	case "winrm":
		c.Pool.Function = WinrmCracker
	case "mongod", "mongodb":
		c.Pool.Function = mongodbCracker
	case "redis":
		c.Pool.Function = redisCracker
	case "smb":
		c.Pool.Function = smbCracker
	}
	if c.Pool.Function == nil {
		c.Pool.OutDone()
		return
	}
	//go 任务下发器
	go func() {
		x1 := c.authList.Dict(c.onlyPassword)
		//fmt.Println("破解任务下发器：", len(x1))
		for _, a := range x1 {
			if c.Pool.Done {
				c.Pool.InDone()
				//fmt.Println("hydra 1：线程结束")
				return
			}
			c.authInfo.Auth = a
			c.Pool.In <- *c.authInfo
		}
		//关闭信道
		c.Pool.InDone()
	}()
	//开始暴力破解
	c.Pool.Run()
}

func InitDefaultAuthMap() {
	m := make(map[string]*AuthList)
	m = map[string]*AuthList{}
	for _, x := range ProtocolList {
		m[x] = GetDefaultFtpList(x)
	}
	//m["rdp"] = GetDefaultFtpList("rdp")
	//m["ssh"] = GetDefaultFtpList("ssh")
	//m["rsh-spx"] = GetDefaultFtpList("ssh")
	//m["mysql"] = GetDefaultFtpList("mysql")
	//m["mssql"] = GetDefaultFtpList("mssql")
	//m["oracle"] = GetDefaultFtpList("oracle")
	//m["postgresql"] = GetDefaultFtpList("postgresql")
	//m["redis"] = GetDefaultFtpList("redis")
	//m["ftp"] = GetDefaultFtpList("ftp")
	//m["mongodb"] = GetDefaultFtpList("mongodb")
	//m["smb"] = GetDefaultFtpList("smb")
	//m["telnet"] = GetDefaultFtpList("telnet")
	DefaultAuthMap = m
}

func InitCustomAuthMap(user, pass []string) {
	CustomAuthMap = NewAuthList()
	CustomAuthMap.Username = user
	CustomAuthMap.Password = pass
}

func Ok(protocol string) bool {
	if misc.IsInStrArr(ProtocolList, protocol) {
		return true
	}
	return false
}

func (c *Cracker) OutWatchDog() {
	count := 0
	var info interface{}
	for out := range c.Pool.Out {
		if out == nil {
			continue
		}
		c.Pool.Stop()
		count += 1
		info = out
	}
	if count > 5 {
		//slog.Printf(slog.DEBUG, "%s://%s:%d,协议不支持", info.(AuthInfo).Protocol, info.(AuthInfo).IPAddr, info.(AuthInfo).Port)
	}
	if count > 0 && count <= 5 {
		c.Out <- info.(AuthInfo)
	}
	close(c.Out)
}

func (c *Cracker) Length() int {
	return c.authList.Length()
}
