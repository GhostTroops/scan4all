package network

import "github.com/sijms/go-ora/v2/network/security"

type SessionContext struct {
	//conn net.Conn
	ConnOption *ConnectionOption
	//PortNo int
	//InstanceName string
	//HostName string
	//IPAddress string
	//Protocol string
	//ServiceName string
	SID []byte
	//ConnectData string
	Version             uint16
	LoVersion           uint16
	Options             uint16
	NegotiatedOptions   uint16
	OurOne              uint16
	Histone             uint16
	ReconAddr           string
	handshakeComplete   bool
	ACFL0               uint8
	ACFL1               uint8
	SessionDataUnit     uint32
	TransportDataUnit   uint32
	UsingAsyncReceivers bool
	IsNTConnected       bool
	OnBreakReset        bool
	GotReset            bool
	AdvancedService     struct {
		CryptAlgo  security.OracleNetworkEncryption
		HashAlgo   security.OracleNetworkDataIntegrity
		SessionKey []byte
		IV         []byte
	}
}

func NewSessionContext(connOption *ConnectionOption) *SessionContext {
	return &SessionContext{
		SessionDataUnit:   connOption.SessionDataUnitSize,
		TransportDataUnit: connOption.TransportDataUnitSize,
		Version:           317,
		LoVersion:         300,
		Options:           1 | 1024 | 2048, /*1024 for urgent data transport*/
		OurOne:            1,
		ConnOption:        connOption,
	}
}
