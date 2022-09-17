package go_ora

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sijms/go-ora/v2/advanced_nego"
	"github.com/sijms/go-ora/v2/converters"
	"github.com/sijms/go-ora/v2/network"
)

type ConnectionState int

const (
	Closed ConnectionState = 0
	Opened ConnectionState = 1
)

type LogonMode int

const (
	NoNewPass   LogonMode = 0x1
	WithNewPass LogonMode = 0x2
	SysDba      LogonMode = 0x20
	SysOper     LogonMode = 0x40
	UserAndPass LogonMode = 0x100
	//PROXY       LogonMode = 0x400
)

type NLSData struct {
	Calender        string
	Comp            string
	Language        string
	LengthSemantics string
	NCharConvExcep  string
	NCharConvImp    string
	DateLang        string
	Sort            string
	Currency        string
	DateFormat      string
	TimeFormat      string
	IsoCurrency     string
	NumericChars    string
	DualCurrency    string
	UnionCurrency   string
	Timestamp       string
	TimestampTZ     string
	TTimezoneFormat string
	NTimezoneFormat string
	Territory       string
	Charset         string
}
type Connection struct {
	State             ConnectionState
	LogonMode         LogonMode
	autoCommit        bool
	conStr            *ConnectionString
	connOption        *network.ConnectionOption
	session           *network.Session
	tcpNego           *TCPNego
	dataNego          *DataTypeNego
	authObject        *AuthObject
	SessionProperties map[string]string
	dBVersion         *DBVersion
	sessionID         int
	serialID          int
	transactionID     []byte
	strConv           converters.IStringConverter
	NLSData           NLSData
	cusTyp            map[string]customType
}

//type OracleDriverContext struct {
//}
type OracleConnector struct {
	drv           *OracleDriver
	connectString string
}
type OracleDriver struct {
	//m         sync.Mutex
	//Conn      *Connection
	//Server    string
	//Port      int
	//Instance  string
	//Service   string
	//DBName    string
	//UserId    string
	//SessionId int
	//SerialNum int
}

func init() {
	sql.Register("oracle", &OracleDriver{})
}

func (drv *OracleDriver) OpenConnector(name string) (driver.Connector, error) {

	return &OracleConnector{drv: drv, connectString: name}, nil
}

func (connector *OracleConnector) Connect(ctx context.Context) (driver.Conn, error) {

	conn, err := NewConnection(connector.connectString)
	if err != nil {
		return nil, err
	}
	err = conn.OpenWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (connector *OracleConnector) Driver() driver.Driver {
	return connector.drv
}

// Open return a new open connection
func (drv *OracleDriver) Open(name string) (driver.Conn, error) {
	conn, err := NewConnection(name)
	if err != nil {
		return nil, err
	}
	//drv.m.Lock()
	//drv.Conn = conn
	//drv.SessionId = conn.sessionID
	//drv.SerialNum = conn.serialID
	//drv.Instance = conn.connOption.InstanceName
	//drv.Server = conn.connOption.Host
	//drv.Port = conn.connOption.Port
	//drv.Service = conn.connOption.ServiceName
	//drv.UserId = conn.connOption.UserID
	//drv.DBName = conn.connOption.DBName
	//drv.m.Unlock()
	err = conn.Open()
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// SetStringConverter this function is used to set a custom string converter interface
// that will used to encode and decode strings and bytearrays
func (conn *Connection) SetStringConverter(converter converters.IStringConverter) {
	conn.strConv = converter
	conn.session.StrConv = converter
}

// GetNLS return NLS properties of the connection.
// this function is left from v1. but v2 is using another method
func (conn *Connection) GetNLS() (*NLSData, error) {

	// we read from nls_session_parameters ONCE
	cmdText := `
DECLARE
	err_code VARCHAR2(2000);
	err_msg  VARCHAR2(2000);
	BEGIN
		SELECT 
			MAX(CASE WHEN PARAMETER='NLS_CALENDAR' THEN VALUE END) AS NLS_CALENDAR,
			MAX(CASE WHEN PARAMETER='NLS_COMP' THEN VALUE END) AS NLS_COMP,
			MAX(CASE WHEN PARAMETER='NLS_LENGTH_SEMANTICS' THEN VALUE END) AS NLS_LENGTH_SEMANTICS,
			MAX(CASE WHEN PARAMETER='NLS_NCHAR_CONV_EXCP' THEN VALUE END) AS NLS_NCHAR_CONV_EXCP,
			MAX(CASE WHEN PARAMETER='NLS_DATE_LANGUAGE' THEN VALUE END) AS NLS_DATE_LANGUAGE,
			MAX(CASE WHEN PARAMETER='NLS_SORT' THEN VALUE END) AS NLS_SORT,
			MAX(CASE WHEN PARAMETER='NLS_CURRENCY' THEN VALUE END) AS NLS_CURRENCY,
			MAX(CASE WHEN PARAMETER='NLS_DATE_FORMAT' THEN VALUE END) AS NLS_DATE_FORMAT,
			MAX(CASE WHEN PARAMETER='NLS_ISO_CURRENCY' THEN VALUE END) AS NLS_ISO_CURRENCY,
			MAX(CASE WHEN PARAMETER='NLS_NUMERIC_CHARACTERS' THEN VALUE END) AS NLS_NUMERIC_CHARACTERS,
			MAX(CASE WHEN PARAMETER='NLS_DUAL_CURRENCY' THEN VALUE END) AS NLS_DUAL_CURRENCY,
			MAX(CASE WHEN PARAMETER='NLS_TIMESTAMP_FORMAT' THEN VALUE END) AS NLS_TIMESTAMP_FORMAT,
			MAX(CASE WHEN PARAMETER='NLS_TIMESTAMP_TZ_FORMAT' THEN VALUE END) AS NLS_TIMESTAMP_TZ_FORMAT,
			'0' AS p_err_code,
			'0' AS p_err_msg
			into :p_nls_calendar, :p_nls_comp, :p_nls_length_semantics, :p_nls_nchar_conv_excep, 
				:p_nls_date_lang, :p_nls_sort, :p_nls_currency, :p_nls_date_format, :p_nls_iso_currency,
				:p_nls_numeric_chars, :p_nls_dual_currency, :p_nls_timestamp, :p_nls_timestamp_tz,
				:p_err_code, :p_err_msg
		FROM
			nls_session_parameters
		;
	END;`
	stmt := NewStmt(cmdText, conn)
	stmt.AddParam("p_nls_calendar", "", 40, Output)
	stmt.AddParam("p_nls_comp", "", 40, Output)
	stmt.AddParam("p_nls_length_semantics", "", 40, Output)
	stmt.AddParam("p_nls_nchar_conv_excep", "", 40, Output)
	stmt.AddParam("p_nls_date_lang", "", 40, Output)
	stmt.AddParam("p_nls_sort", "", 40, Output)
	stmt.AddParam("p_nls_currency", "", 40, Output)
	stmt.AddParam("p_nls_date_format", "", 40, Output)
	stmt.AddParam("p_nls_iso_currency", "", 40, Output)
	stmt.AddParam("p_nls_numeric_chars", "", 40, Output)
	stmt.AddParam("p_nls_dual_currency", "", 40, Output)
	stmt.AddParam("p_nls_timestamp", "", 48, Output)
	stmt.AddParam("p_nls_timestamp_tz", "", 56, Output)
	stmt.AddParam("p_err_code", "", 2000, Output)
	stmt.AddParam("p_err_msg", "", 2000, Output)
	defer func(stmt *Stmt) {
		_ = stmt.Close()
	}(stmt)
	//fmt.Println(stmt.Pars)
	_, err := stmt.Exec(nil)
	if err != nil {
		return nil, err
	}

	if len(stmt.Pars) >= 10 {
		conn.NLSData.Calender = conn.strConv.Decode(stmt.Pars[0].BValue)
		conn.NLSData.Comp = conn.strConv.Decode(stmt.Pars[1].BValue)
		conn.NLSData.LengthSemantics = conn.strConv.Decode(stmt.Pars[2].BValue)
		conn.NLSData.NCharConvExcep = conn.strConv.Decode(stmt.Pars[3].BValue)
		conn.NLSData.DateLang = conn.strConv.Decode(stmt.Pars[4].BValue)
		conn.NLSData.Sort = conn.strConv.Decode(stmt.Pars[5].BValue)
		conn.NLSData.Currency = conn.strConv.Decode(stmt.Pars[6].BValue)
		conn.NLSData.DateFormat = conn.strConv.Decode(stmt.Pars[7].BValue)
		conn.NLSData.IsoCurrency = conn.strConv.Decode(stmt.Pars[8].BValue)
		conn.NLSData.NumericChars = conn.strConv.Decode(stmt.Pars[9].BValue)
		conn.NLSData.DualCurrency = conn.strConv.Decode(stmt.Pars[10].BValue)
		conn.NLSData.Timestamp = conn.strConv.Decode(stmt.Pars[11].BValue)
		conn.NLSData.TimestampTZ = conn.strConv.Decode(stmt.Pars[12].BValue)
	}

	/*
		for _, par := range stmt.Pars {
			if par.Name == "p_nls_calendar" {
				conn.NLSData.Calender = conn.strConv.Decode(par.BValue)
			} else if par.Name == "p_nls_comp" {
				conn.NLSData.Comp = conn.strConv.Decode(par.BValue)
			} else if par.Name == "p_nls_length_semantics" {
				conn.NLSData.LengthSemantics = conn.strConv.Decode(par.BValue)
			} else if par.Name == "p_nls_nchar_conv_excep" {
				conn.NLSData.NCharConvExcep = conn.strConv.Decode(par.BValue)
			} else if par.Name == "p_nls_date_lang" {
				conn.NLSData.DateLang = conn.strConv.Decode(par.BValue)
			} else if par.Name == "p_nls_sort" {
				conn.NLSData.Sort = conn.strConv.Decode(par.BValue)
			} else if par.Name == "p_nls_currency" {
				conn.NLSData.Currency = conn.strConv.Decode(par.BValue)
			} else if par.Name == "p_nls_date_format" {
				conn.NLSData.DateFormat = conn.strConv.Decode(par.BValue)
			} else if par.Name == "p_nls_iso_currency" {
				conn.NLSData.IsoCurrency = conn.strConv.Decode(par.BValue)
			} else if par.Name == "p_nls_numeric_chars" {
				conn.NLSData.NumericChars = conn.strConv.Decode(par.BValue)
			} else if par.Name == "p_nls_dual_currency" {
				conn.NLSData.DualCurrency = conn.strConv.Decode(par.BValue)
			} else if par.Name == "p_nls_timestamp" {
				conn.NLSData.Timestamp = conn.strConv.Decode(par.BValue)
			} else if par.Name == "p_nls_timestamp_tz" {
				conn.NLSData.TimestampTZ = conn.strConv.Decode(par.BValue)
			}
		}
	*/

	return &conn.NLSData, nil
}

// Prepare take a query string and create a stmt object
func (conn *Connection) Prepare(query string) (driver.Stmt, error) {
	conn.connOption.Tracer.Print("Prepare\n", query)
	return NewStmt(query, conn), nil
}

// Ping test if connection is online
func (conn *Connection) Ping(ctx context.Context) error {
	conn.connOption.Tracer.Print("Ping")
	conn.session.ResetBuffer()
	conn.session.StartContext(ctx)
	defer conn.session.EndContext()
	return (&simpleObject{
		connection:  conn,
		operationID: 0x93,
		data:        nil,
	}).write().read()
}

//func (conn *Connection) Logoff() error {
//	conn.connOption.Tracer.Print("Logoff")
//	session := conn.session
//	session.ResetBuffer()
//	session.PutBytes(0x11, 0x87, 0, 0, 0, 0x2, 0x1, 0x11, 0x1, 0, 0, 0, 0x1, 0, 0, 0, 0, 0, 0x1, 0, 0, 0, 0, 0,
//		3, 9, 0)
//	err := session.Write()
//	if err != nil {
//		return err
//	}
//	loop := true
//	for loop {
//		msg, err := session.GetByte()
//		if err != nil {
//			return err
//		}
//		switch msg {
//		case 4:
//			session.Summary, err = network.NewSummary(session)
//			if err != nil {
//				return err
//			}
//			loop = false
//		case 9:
//			if session.HasEOSCapability {
//				if session.Summary == nil {
//					session.Summary = new(network.SummaryObject)
//				}
//				session.Summary.EndOfCallStatus, err = session.GetInt(4, true, true)
//				if err != nil {
//					return err
//				}
//			}
//			if session.HasFSAPCapability {
//				if session.Summary == nil {
//					session.Summary = new(network.SummaryObject)
//				}
//				session.Summary.EndToEndECIDSequence, err = session.GetInt(2, true, true)
//				if err != nil {
//					return err
//				}
//			}
//			loop = false
//		default:
//			return errors.New(fmt.Sprintf("message code error: received code %d and expected code is 4, 9", msg))
//		}
//	}
//	if session.HasError() {
//		return errors.New(session.GetError())
//	}
//	return nil
//}

// Open open the connection = bring it online
func (conn *Connection) Open() error {
	return conn.OpenWithContext(context.Background())
}

// OpenWithContext open the connection with timeout context
func (conn *Connection) OpenWithContext(ctx context.Context) error {
	tracer := conn.connOption.Tracer
	switch conn.conStr.DBAPrivilege {
	case SYSDBA:
		conn.LogonMode |= SysDba
	case SYSOPER:
		conn.LogonMode |= SysOper
	default:
		conn.LogonMode = 0
	}

	conn.session = network.NewSession(conn.connOption)
	W := conn.conStr.w
	if conn.connOption.SSL && W != nil {
		err := conn.session.LoadSSLData(W.certificates, W.privateKeys, W.certificateRequests)
		if err != nil {
			return err
		}
	}
	session := conn.session
	err := session.Connect(ctx)
	if err != nil {
		return err
	}
	// advanced negotiation
	if session.Context.ACFL0&1 != 0 && session.Context.ACFL0&4 == 0 && session.Context.ACFL1&8 == 0 {
		tracer.Print("Advance Negotiation")
		ano, err := advanced_nego.NewAdvNego(session)
		if err != nil {
			return err
		}
		err = ano.Write()
		if err != nil {
			return err
		}
		err = ano.Read()
		if err != nil {
			return err
		}
		err = ano.StartServices()
		if err != nil {
			return err
		}
	}

	tracer.Print("TCP Negotiation")
	conn.tcpNego, err = newTCPNego(conn.session)
	if err != nil {
		return err
	}
	tracer.Print("Server Charset: ", conn.tcpNego.ServerCharset)
	tracer.Print("Server National Charset: ", conn.tcpNego.ServernCharset)
	// create string converter object
	conn.strConv = converters.NewStringConverter(conn.tcpNego.ServerCharset)
	conn.session.StrConv = conn.strConv
	conn.tcpNego.ServerFlags |= 2
	tracer.Print("Data Type Negotiation")
	conn.dataNego = buildTypeNego(conn.tcpNego, conn.session)
	err = conn.dataNego.write(conn.session)
	if err != nil {
		return err
	}
	err = conn.dataNego.read(conn.session)
	if err != nil {
		return err
	}
	conn.session.TTCVersion = conn.dataNego.CompileTimeCaps[7]
	conn.session.UseBigScn = conn.tcpNego.ServerCompileTimeCaps[7] >= 8
	if conn.tcpNego.ServerCompileTimeCaps[7] < conn.session.TTCVersion {
		conn.session.TTCVersion = conn.tcpNego.ServerCompileTimeCaps[7]
	}
	tracer.Print("TTC Version: ", conn.session.TTCVersion)
	if len(conn.tcpNego.ServerRuntimeCaps) > 6 && conn.tcpNego.ServerRuntimeCaps[6]&4 == 4 {
		converters.MAX_LEN_VARCHAR2 = 0x7FFF
		converters.MAX_LEN_NVARCHAR2 = 0x7FFF
		converters.MAX_LEN_RAW = 0x7FFF
	} else {
		converters.MAX_LEN_VARCHAR2 = 0xFA0
		converters.MAX_LEN_NVARCHAR2 = 0xFA0
		converters.MAX_LEN_RAW = 0xFA0
	}
	//this.m_b32kTypeSupported = this.m_dtyNeg.m_b32kTypeSupported;
	//this.m_bSupportSessionStateOps = this.m_dtyNeg.m_bSupportSessionStateOps;
	//this.m_marshallingEngine.m_bServerUsingBigSCN = this.m_serverCompiletimeCapabilities[7] >= (byte) 8;
	//if len(conn.connOption.UserID) > 0 && len(conn.conStr.password) > 0 {
	//
	//} else {
	//	err = conn.doOsAuth()
	//}
	err = conn.doAuth()
	if err != nil {
		return err
	}
	conn.State = Opened
	conn.dBVersion, err = GetDBVersion(conn.session)
	if err != nil {
		return err
	}
	tracer.Print("Connected")
	tracer.Print("Database Version: ", conn.dBVersion.Text)
	sessionID, err := strconv.ParseUint(conn.SessionProperties["AUTH_SESSION_ID"], 10, 32)
	if err != nil {
		return err
	}
	conn.sessionID = int(sessionID)
	serialNum, err := strconv.ParseUint(conn.SessionProperties["AUTH_SERIAL_NUM"], 10, 32)
	if err != nil {
		return err
	}
	conn.serialID = int(serialNum)
	conn.connOption.InstanceName = conn.SessionProperties["AUTH_SC_INSTANCE_NAME"]
	//conn.connOption.Host = conn.SessionProperties["AUTH_SC_SERVER_HOST"]
	conn.connOption.ServiceName = conn.SessionProperties["AUTH_SC_SERVICE_NAME"]
	conn.connOption.DomainName = conn.SessionProperties["AUTH_SC_DB_DOMAIN"]
	conn.connOption.DBName = conn.SessionProperties["AUTH_SC_DBUNIQUE_NAME"]
	if len(conn.NLSData.Language) == 0 {
		_, err = conn.GetNLS()
		if err != nil {
			return err
		}
	}
	return nil
}

// Begin called to begin a transaction
func (conn *Connection) Begin() (driver.Tx, error) {
	conn.connOption.Tracer.Print("Begin transaction")
	conn.autoCommit = false
	return &Transaction{conn: conn, ctx: context.Background()}, nil
}

func (conn *Connection) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if opts.ReadOnly {
		return nil, errors.New("readonly transaction is not supported")
	}
	if opts.Isolation != 0 {
		return nil, errors.New("only support default value for isolation")
	}
	conn.connOption.Tracer.Print("Begin transaction with context")
	conn.autoCommit = false
	return &Transaction{conn: conn, ctx: ctx}, nil
}

// NewConnection create a new connection from databaseURL string
func NewConnection(databaseUrl string) (*Connection, error) {
	//this.m_id = this.GetHashCode().ToString();
	conStr, err := newConnectionStringFromUrl(databaseUrl)
	if err != nil {
		return nil, err
	}
	//userName := ""
	//User, err := user.Current()
	//if err == nil {
	//	userName = User.Username
	//}
	//fmt.Println(userName)
	//idx := strings.Index(userName, "\\")
	//if idx >= 0 {
	//	userName = userName[idx+1:]
	//}
	//hostName, _ := os.Hostname()
	//indexOfSlash := strings.LastIndex(os.Args[0], "/")
	//indexOfSlash += 1
	//if indexOfSlash < 0 {
	//	indexOfSlash = 0
	//}

	//connOption := &network.ConnectionOption{
	//	//Port:                  conStr.Port,
	//	Servers:               conStr.Servers,
	//	Ports:                 conStr.Ports,
	//	TransportConnectTo:    0xFFFF,
	//	SSLVersion:            "",
	//	WalletDict:            "",
	//	TransportDataUnitSize: 0xFFFF,
	//	SessionDataUnitSize:   0xFFFF,
	//	Protocol:              "tcp",
	//	UserID: conStr.UserID, 		"",
	//	SID: conStr.SID,
	//	ServiceName:  conStr.ServiceName,
	//	InstanceName: conStr.InstanceName,
	//	PrefetchRows: conStr.PrefetchRows,
	//	ClientData: network.ClientInfo{
	//		ProgramPath: os.Args[0],
	//		ProgramName: os.Args[0][indexOfSlash:],
	//		UserName:    userName,
	//		HostName:    hostName,
	//		DriverName:  "OracleClientGo",
	//		PID:         os.Getpid(),
	//	},
	//	SSL:       conStr.SSL,
	//	SSLVerify: conStr.SSLVerify,
	//	//InAddrAny:             false,
	//}

	return &Connection{
		State:      Closed,
		conStr:     conStr,
		connOption: &conStr.connOption,
		autoCommit: true,
		//w:          conStr.w,
		cusTyp: map[string]customType{},
	}, nil
}

// Close the connection by disconnect network session
func (conn *Connection) Close() (err error) {
	conn.connOption.Tracer.Print("Close")
	//var err error = nil
	if conn.session != nil {
		//err = conn.Logoff()
		conn.session.Disconnect()
		conn.session = nil
	}
	conn.connOption.Tracer.Print("Connection Closed")
	_ = conn.connOption.Tracer.Close()
	return
}

// doOsAuth a login step that use os authentication
//func (conn *Connection) doOsAuth() error {
//	conn.connOption.Tracer.Print("doOsAuth")
//	conn.session.ResetBuffer()
//	conn.session.PutBytes(3, 0x73, 0)
//	if len(conn.connOption.UserID) > 0 {
//		conn.session.PutBytes(1)
//		conn.session.PutUint(len(conn.connOption.UserID), 4, true, true)
//	} else {
//		conn.session.PutBytes(0, 0)
//	}
//	if len(conn.connOption.UserID) > 0 && len(conn.conStr.password) > 0 {
//		conn.LogonMode |= 0x100
//	}
//	conn.LogonMode = conn.LogonMode | NoNewPass
//	conn.session.PutUint(int(conn.LogonMode), 4, true, true)
//	conn.session.PutBytes(1)
//	conn.session.PutBytes(1, 12, 1, 1)
//	if len(conn.connOption.UserID) > 0 {
//		conn.session.PutString(conn.connOption.UserID)
//	}
//	conn.session.PutKeyValString("AUTH_TERMINAL", conn.connOption.HostName, 0)
//	conn.session.PutKeyValString("AUTH_PROGRAM_NM", conn.connOption.ProgramName, 0)
//	conn.session.PutKeyValString("AUTH_MACHINE", conn.connOption.HostName, 0)
//	conn.session.PutKeyValString("AUTH_PID", fmt.Sprintf("%d", conn.connOption.PID), 0)
//	conn.session.PutKeyValString("AUTH_SID", conn.connOption.ClientInfo.UserName, 0)
//	conn.session.PutKeyValString("AUTH_CONNECT_STRING", conn.connOption.ConnectionData(), 0)
//	conn.session.PutKeyValString("SESSION_CLIENT_CHARSET", strconv.Itoa(conn.tcpNego.ServerCharset), 0)
//	conn.session.PutKeyValString("SESSION_CLIENT_LIB_TYPE", "0", 0)
//	conn.session.PutKeyValString("SESSION_CLIENT_DRIVER_NAME", "OracleClientGo", 0)
//	conn.session.PutKeyValString("SESSION_CLIENT_VERSION", "0", 0)
//	conn.session.PutKeyValString("SESSION_CLIENT_LOBATTR", "1", 0)
//	//conn.session.PutKeyValString("AUTH_ACL", "8800", 0)
//	alterSess := "ALTER SESSION SET NLS_LANGUAGE='AMERICAN' NLS_TERRITORY='AMERICA' TIME_ZONE='Africa/Cairo'\x00"
//	conn.session.PutKeyValString("AUTH_ALTER_SESSION", alterSess, 1)
//	err := conn.session.Write()
//	if err != nil {
//		return err
//	}
//
//	conn.authObject, err = newAuthObject(conn.connOption.UserID, conn.conStr.password, conn.tcpNego, conn.session)
//	if err != nil {
//		return err
//	}
//	// if proxyAuth ==> mode |= PROXY
//	err = conn.authObject.Write(conn.connOption, conn.LogonMode, conn.session)
//	if err != nil {
//		return err
//	}
//	stop := false
//	for !stop {
//		msg, err := conn.session.GetByte()
//		if err != nil {
//			return err
//		}
//		switch msg {
//		case 4:
//			conn.session.Summary, err = network.NewSummary(conn.session)
//			if err != nil {
//				return err
//			}
//			if conn.session.HasError() {
//				return conn.session.GetError()
//			}
//			stop = true
//		case 8:
//			dictLen, err := conn.session.GetInt(2, true, true)
//			if err != nil {
//				return err
//			}
//			conn.SessionProperties = make(map[string]string, dictLen)
//			for x := 0; x < dictLen; x++ {
//				key, val, _, err := conn.session.GetKeyVal()
//				if err != nil {
//					return err
//				}
//				conn.SessionProperties[string(key)] = string(val)
//			}
//		case 15:
//			warning, err := network.NewWarningObject(conn.session)
//			if err != nil {
//				return err
//			}
//			if warning != nil {
//				fmt.Println(warning)
//			}
//		case 23:
//			opCode, err := conn.session.GetByte()
//			if err != nil {
//				return err
//			}
//			if opCode == 5 {
//				err = conn.loadNLSData()
//				if err != nil {
//					return err
//				}
//			} else {
//				err = conn.getServerNetworkInformation(opCode)
//				if err != nil {
//					return err
//				}
//			}
//		default:
//			return errors.New(fmt.Sprintf("message code error: received code %d", msg))
//		}
//	}
//
//	// if verifyResponse == true
//	// conn.authObject.VerifyResponse(conn.SessionProperties["AUTH_SVR_RESPONSE"])
//	return nil
//}
// doAuth a login step that occur during open connection
func (conn *Connection) doAuth() error {
	conn.connOption.Tracer.Print("doAuth")
	if len(conn.connOption.UserID) > 0 && len(conn.conStr.password) > 0 {
		conn.session.ResetBuffer()
		conn.session.PutBytes(3, 0x76, 0, 1)
		conn.session.PutUint(len(conn.connOption.UserID), 4, true, true)
		conn.LogonMode = conn.LogonMode | NoNewPass
		conn.session.PutUint(int(conn.LogonMode), 4, true, true)
		conn.session.PutBytes(1, 1, 5, 1, 1)
		if len(conn.connOption.UserID) > 0 {
			conn.session.PutString(conn.connOption.UserID)
		}
		conn.session.PutKeyValString("AUTH_TERMINAL", conn.connOption.ClientInfo.HostName, 0)
		conn.session.PutKeyValString("AUTH_PROGRAM_NM", conn.connOption.ClientInfo.ProgramName, 0)
		conn.session.PutKeyValString("AUTH_MACHINE", conn.connOption.ClientInfo.HostName, 0)
		conn.session.PutKeyValString("AUTH_PID", fmt.Sprintf("%d", conn.connOption.ClientInfo.PID), 0)
		conn.session.PutKeyValString("AUTH_SID", conn.connOption.ClientInfo.UserName, 0)
		err := conn.session.Write()
		if err != nil {
			return err
		}

		conn.authObject, err = newAuthObject(conn.connOption.UserID, conn.conStr.password, conn.tcpNego, conn)
		if err != nil {
			return err
		}
	} else {
		conn.authObject = &AuthObject{
			tcpNego:    conn.tcpNego,
			usePadding: false,
			customHash: conn.tcpNego.ServerCompileTimeCaps[4]&32 != 0,
		}
	}
	// if proxyAuth ==> mode |= PROXY
	err := conn.authObject.Write(conn.connOption, conn.LogonMode, conn.session)
	if err != nil {
		return err
	}
	stop := false
	for !stop {
		msg, err := conn.session.GetByte()
		if err != nil {
			return err
		}
		switch msg {
		case 4:
			conn.session.Summary, err = network.NewSummary(conn.session)
			if err != nil {
				return err
			}
			if conn.session.HasError() {
				return conn.session.GetError()
			}
			stop = true
		case 8:
			dictLen, err := conn.session.GetInt(2, true, true)
			if err != nil {
				return err
			}
			conn.SessionProperties = make(map[string]string, dictLen)
			for x := 0; x < dictLen; x++ {
				key, val, _, err := conn.session.GetKeyVal()
				if err != nil {
					return err
				}
				conn.SessionProperties[string(key)] = string(val)
			}
		case 15:
			warning, err := network.NewWarningObject(conn.session)
			if err != nil {
				return err
			}
			if warning != nil {
				fmt.Println(warning)
			}
		case 23:
			opCode, err := conn.session.GetByte()
			if err != nil {
				return err
			}
			if opCode == 5 {
				err = conn.loadNLSData()
				if err != nil {
					return err
				}
			} else {
				err = conn.getServerNetworkInformation(opCode)
				if err != nil {
					return err
				}
			}
		default:
			return errors.New(fmt.Sprintf("message code error: received code %d", msg))
		}
	}

	// if verifyResponse == true
	// conn.authObject.VerifyResponse(conn.SessionProperties["AUTH_SVR_RESPONSE"])
	return nil
}

// loadNLSData get nls data for v2
func (conn *Connection) loadNLSData() error {
	_, err := conn.session.GetInt(2, true, true)
	if err != nil {
		return err
	}
	_, err = conn.session.GetByte()
	if err != nil {
		return err
	}
	length, err := conn.session.GetInt(4, true, true)
	if err != nil {
		return err
	}
	_, err = conn.session.GetByte()
	if err != nil {
		return err
	}
	for i := 0; i < length; i++ {
		nlsKey, nlsVal, nlsCode, err := conn.session.GetKeyVal()
		if err != nil {
			return err
		}
		conn.NLSData.SaveNLSValue(string(nlsKey), string(nlsVal), nlsCode)
	}
	_, err = conn.session.GetInt(4, true, true)
	return err
}

func (conn *Connection) getServerNetworkInformation(code uint8) error {
	session := conn.session
	if code == 0 {
		_, err := session.GetByte()
		return err
	}
	switch code - 1 {
	case 1:
		// receive OCOSPID
		length, err := session.GetInt(2, true, true)
		if err != nil {
			return err
		}
		_, err = session.GetByte()
		if err != nil {
			return err
		}
		_, err = session.GetBytes(length)
		if err != nil {
			return err
		}
	case 3:
		// receive OCSESSRET session return values
		_, err := session.GetInt(2, true, true)
		if err != nil {
			return err
		}
		_, err = session.GetByte()
		if err != nil {
			return err
		}
		length, err := session.GetInt(2, true, true)
		if err != nil {
			return err
		}
		// get nls data
		for i := 0; i < length; i++ {
			nlsKey, nlsVal, nlsCode, err := session.GetKeyVal()
			if err != nil {
				return err
			}
			conn.NLSData.SaveNLSValue(string(nlsKey), string(nlsVal), nlsCode)
		}
		flag, err := session.GetInt(4, true, true)
		if err != nil {
			return err
		}
		sessionID, err := session.GetInt(4, true, true)
		if err != nil {
			return err
		}
		serialID, err := session.GetInt(2, true, true)
		if err != nil {
			return err
		}
		if flag&4 == 4 {
			conn.sessionID = sessionID
			conn.serialID = serialID
			// save session id and serial number to connection
		}
	case 4:
		err := conn.loadNLSData()
		if err != nil {
			return err
		}
	case 6:
		length, err := session.GetInt(4, true, true)
		if err != nil {
			return err
		}
		conn.transactionID, err = session.GetClr()
		if len(conn.transactionID) > length {
			conn.transactionID = conn.transactionID[:length]
		}
	case 7:
		_, err := session.GetInt(2, true, true)
		if err != nil {
			return err
		}
		_, err = session.GetByte()
		if err != nil {
			return err
		}
		_, err = session.GetInt(4, true, true)
		if err != nil {
			return err
		}
		_, err = session.GetInt(4, true, true)
		if err != nil {
			return err
		}
		_, err = session.GetByte()
		if err != nil {
			return err
		}
		_, err = session.GetDlc()
		if err != nil {
			return err
		}
	case 8:
		_, err := session.GetInt(2, true, true)
		if err != nil {
			return err
		}
		_, err = session.GetByte()
		if err != nil {
			return err
		}
	}
	return nil
}

// SaveNLSValue a helper function that convert between nls key and code
func (nls *NLSData) SaveNLSValue(key, value string, code int) {
	key = strings.ToUpper(key)
	if len(key) > 0 {
		switch key {
		case "AUTH_NLS_LXCCURRENCY":
			code = 0
		case "AUTH_NLS_LXCISOCURR":
			code = 1
		case "AUTH_NLS_LXCNUMERICS":
			code = 2
		case "AUTH_NLS_LXCDATEFM":
			code = 7
		case "AUTH_NLS_LXCDATELANG":
			code = 8
		case "AUTH_NLS_LXCTERRITORY":
			code = 9
		case "SESSION_NLS_LXCCHARSET":
			code = 10
		case "AUTH_NLS_LXCSORT":
			code = 11
		case "AUTH_NLS_LXCCALENDAR":
			code = 12
		case "AUTH_NLS_LXLAN":
			code = 16
		case "AL8KW_NLSCOMP":
			code = 50
		case "AUTH_NLS_LXCUNIONCUR":
			code = 52
		case "AUTH_NLS_LXCTIMEFM":
			code = 57
		case "AUTH_NLS_LXCSTMPFM":
			code = 58
		case "AUTH_NLS_LXCTTZNFM":
			code = 59
		case "AUTH_NLS_LXCSTZNFM":
			code = 60
		case "SESSION_NLS_LXCNLSLENSEM":
			code = 61
		case "SESSION_NLS_LXCNCHAREXCP":
			code = 62
		case "SESSION_NLS_LXCNCHARIMP":
			code = 63
		}
	}
	switch code {
	case 0:
		nls.Currency = value
	case 1:
		nls.IsoCurrency = value
	case 2:
		nls.NumericChars = value
	case 7:
		nls.DateFormat = value
	case 8:
		nls.DateLang = value
	case 9:
		nls.Territory = value
	case 10:
		nls.Charset = value
	case 11:
		nls.Sort = value
	case 12:
		nls.Calender = value
	case 16:
		nls.Language = value
	case 50:
		nls.Comp = value
	case 52:
		nls.UnionCurrency = value
	case 57:
		nls.TimeFormat = value
	case 58:
		nls.Timestamp = value
	case 59:
		nls.TTimezoneFormat = value
	case 60:
		nls.NTimezoneFormat = value
	case 61:
		nls.LengthSemantics = value
	case 62:
		nls.NCharConvExcep = value
	case 63:
		nls.NCharConvImp = value
	}
}

func (conn *Connection) Exec(text string, args ...driver.Value) (driver.Result, error) {
	stmt := NewStmt(text, conn)
	defer func() {
		_ = stmt.Close()
	}()
	return stmt.Exec(args)
}

func SetNTSAuth(newNTSManager advanced_nego.NTSAuthInterface) {
	advanced_nego.NTSAuth = newNTSManager
}

// all columns should pass as an array of values
func (conn *Connection) BulkInsert(sqlText string, rowNum int, columns ...[]driver.Value) (*QueryResult, error) {
	if conn.State != Opened {
		return nil, &network.OracleError{ErrCode: 6413, ErrMsg: "ORA-06413: Connection not open"}
	}
	if rowNum == 0 {
		return nil, nil
	}
	stmt := NewStmt(sqlText, conn)
	stmt.arrayBindCount = rowNum
	defer func() {
		_ = stmt.Close()
	}()
	tracer := conn.connOption.Tracer
	tracer.Printf("BulkInsert:\n%s", stmt.text)
	tracer.Printf("Row Num: %d", rowNum)
	tracer.Printf("Column Num: %d", len(columns))
	for idx, col := range columns {
		if len(col) < rowNum {
			return nil, fmt.Errorf("size of column no. %d is less than rowNum", idx)
		}

		par, err := stmt.NewParam("", col[0], 0, Input)
		if err != nil {
			return nil, err
		}
		maxLen := par.MaxLen
		maxCharLen := par.MaxCharLen
		for index, val := range col {
			if index == 0 {
				continue
			}
			err = par.encodeValue(val, 0, conn)
			if err != nil {
				return nil, err
			}
			if maxLen < par.MaxLen {
				maxLen = par.MaxLen
			}
			if maxCharLen < par.MaxCharLen {
				maxCharLen = par.MaxCharLen
			}
		}

		_ = par.encodeValue(col[0], 0, conn)
		par.MaxLen = maxLen
		par.MaxCharLen = maxCharLen
		stmt.Pars = append(stmt.Pars, *par)
	}
	session := conn.session
	session.ResetBuffer()
	err := stmt.basicWrite(stmt.getExeOption(), stmt.parse, stmt.define)
	for x := 0; x < rowNum; x++ {
		for idx, col := range columns {
			err = stmt.Pars[idx].encodeValue(col[x], 0, conn)
			if err != nil {
				return nil, err
			}
		}
		err = stmt.writePars(session)
		if err != nil {
			return nil, err
		}
	}
	err = session.Write()
	if err != nil {
		return nil, err
	}
	dataSet := new(DataSet)
	err = stmt.read(dataSet)
	if err != nil {
		return nil, err
	}
	result := new(QueryResult)
	if session.Summary != nil {
		result.rowsAffected = int64(session.Summary.CurRowNumber)
	}
	return result, nil
}

func (conn *Connection) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	stmt := NewStmt(query, conn)
	stmt.autoClose = true
	defer func() {
		_ = stmt.Close()
	}()
	return stmt.ExecContext(ctx, args)
}

func (conn *Connection) CheckNamedValue(named *driver.NamedValue) error {
	return nil
}

func (conn *Connection) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	stmt := NewStmt(query, conn)
	stmt.autoClose = true
	return stmt.QueryContext(ctx, args)
}

func (conn *Connection) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if conn.State != Opened {
		return nil, &network.OracleError{ErrCode: 6413, ErrMsg: "ORA-06413: Connection not open"}
	}
	conn.connOption.Tracer.Print("Prepare With Context\n", query)
	conn.session.StartContext(ctx)
	defer conn.session.EndContext()
	return NewStmt(query, conn), nil
}
