package t125

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/hktalent/scan4all/pkg/kscan/lib/grdp/core"
	"github.com/hktalent/scan4all/pkg/kscan/lib/grdp/emission"
	"github.com/hktalent/scan4all/pkg/kscan/lib/grdp/glog"
	"github.com/hktalent/scan4all/pkg/kscan/lib/grdp/protocol/t125/ber"
	"github.com/hktalent/scan4all/pkg/kscan/lib/grdp/protocol/t125/gcc"
	"github.com/hktalent/scan4all/pkg/kscan/lib/grdp/protocol/t125/per"
)

// take idea from https://github.com/Madnikulin50/gordp

// Multiple Channel Service layer

type MCSMessage uint8

const (
	MCS_TYPE_CONNECT_INITIAL  MCSMessage = 0x65
	MCS_TYPE_CONNECT_RESPONSE            = 0x66
)

type MCSDomainPDU uint16

const (
	ERECT_DOMAIN_REQUEST          MCSDomainPDU = 1
	DISCONNECT_PROVIDER_ULTIMATUM              = 8
	ATTACH_USER_REQUEST                        = 10
	ATTACH_USER_CONFIRM                        = 11
	CHANNEL_JOIN_REQUEST                       = 14
	CHANNEL_JOIN_CONFIRM                       = 15
	SEND_DATA_REQUEST                          = 25
	SEND_DATA_INDICATION                       = 26
)

const (
	MCS_GLOBAL_CHANNEL   uint16 = 1003
	MCS_USERCHANNEL_BASE        = 1001
)

/**
 * Format MCS PDULayer header packet
 * @param mcsPdu {integer}
 * @param options {integer}
 * @returns {type.UInt8} headers
 */
func writeMCSPDUHeader(mcsPdu MCSDomainPDU, options uint8, w io.Writer) {
	core.WriteUInt8((uint8(mcsPdu)<<2)|options, w)
}

func readMCSPDUHeader(options uint8, mcsPdu MCSDomainPDU) bool {
	return (options >> 2) == uint8(mcsPdu)
}

type DomainParameters struct {
	MaxChannelIds   int
	MaxUserIds      int
	MaxTokenIds     int
	NumPriorities   int
	MinThoughput    int
	MaxHeight       int
	MaxMCSPDUsize   int
	ProtocolVersion int
}

/**
 * @see http://www.itu.int/rec/T-REC-T.125-199802-I/en page 25
 * @returns {asn1.univ.Sequence}
 */
func NewDomainParameters(
	maxChannelIds int,
	maxUserIds int,
	maxTokenIds int,
	numPriorities int,
	minThoughput int,
	maxHeight int,
	maxMCSPDUsize int,
	protocolVersion int) *DomainParameters {
	return &DomainParameters{maxChannelIds, maxUserIds, maxTokenIds,
		numPriorities, minThoughput, maxHeight, maxMCSPDUsize, protocolVersion}
}

func (d *DomainParameters) BER() []byte {
	buff := &bytes.Buffer{}
	ber.WriteInteger(d.MaxChannelIds, buff)
	ber.WriteInteger(d.MaxUserIds, buff)
	ber.WriteInteger(d.MaxTokenIds, buff)
	ber.WriteInteger(1, buff)
	ber.WriteInteger(0, buff)
	ber.WriteInteger(1, buff)
	ber.WriteInteger(d.MaxMCSPDUsize, buff)
	ber.WriteInteger(2, buff)
	return buff.Bytes()
}

func ReadDomainParameters(r io.Reader) (*DomainParameters, error) {
	if !ber.ReadUniversalTag(ber.TAG_SEQUENCE, true, r) {
		return nil, errors.New("bad BER tags")
	}
	d := &DomainParameters{}
	ber.ReadLength(r)

	d.MaxChannelIds, _ = ber.ReadInteger(r)
	d.MaxUserIds, _ = ber.ReadInteger(r)
	d.MaxTokenIds, _ = ber.ReadInteger(r)
	ber.ReadInteger(r)
	ber.ReadInteger(r)
	ber.ReadInteger(r)
	d.MaxMCSPDUsize, _ = ber.ReadInteger(r)
	ber.ReadInteger(r)
	return d, nil
}

/**
 * @see http://www.itu.int/rec/T-REC-T.125-199802-I/en page 25
 * @param userData {Buffer}
 * @returns {asn1.univ.Sequence}
 */
type ConnectInitial struct {
	CallingDomainSelector []byte
	CalledDomainSelector  []byte
	UpwardFlag            bool
	TargetParameters      DomainParameters
	MinimumParameters     DomainParameters
	MaximumParameters     DomainParameters
	UserData              []byte
}

func NewConnectInitial(userData []byte) ConnectInitial {
	return ConnectInitial{[]byte{0x1},
		[]byte{0x1},
		true,
		*NewDomainParameters(34, 2, 0, 1, 0, 1, 0xffff, 2),
		*NewDomainParameters(1, 1, 1, 1, 0, 1, 0x420, 2),
		*NewDomainParameters(0xffff, 0xfc17, 0xffff, 1, 0, 1, 0xffff, 2),
		userData}
}

func (c *ConnectInitial) BER() []byte {
	buff := &bytes.Buffer{}
	ber.WriteOctetstring(string(c.CallingDomainSelector), buff)
	ber.WriteOctetstring(string(c.CalledDomainSelector), buff)
	ber.WriteBoolean(c.UpwardFlag, buff)
	ber.WriteEncodedDomainParams(c.TargetParameters.BER(), buff)
	ber.WriteEncodedDomainParams(c.MinimumParameters.BER(), buff)
	ber.WriteEncodedDomainParams(c.MaximumParameters.BER(), buff)
	ber.WriteOctetstring(string(c.UserData), buff)
	return buff.Bytes()
}

/**
 * @see http://www.itu.int/rec/T-REC-T.125-199802-I/en page 25
 * @returns {asn1.univ.Sequence}
 */

type ConnectResponse struct {
	result           uint8
	calledConnectId  int
	domainParameters *DomainParameters
	userData         []byte
}

func NewConnectResponse(userData []byte) *ConnectResponse {
	return &ConnectResponse{0,
		0,
		NewDomainParameters(22, 3, 0, 1, 0, 1, 0xfff8, 2),
		userData}
}

func ReadConnectResponse(r io.Reader) (*ConnectResponse, error) {
	c := &ConnectResponse{}
	var err error
	_, err = ber.ReadApplicationTag(MCS_TYPE_CONNECT_RESPONSE, r)
	if err != nil {
		return nil, err
	}
	c.result, err = ber.ReadEnumerated(r)
	if err != nil {
		return nil, err
	}

	c.calledConnectId, err = ber.ReadInteger(r)
	c.domainParameters, err = ReadDomainParameters(r)
	if err != nil {
		return nil, err
	}
	if !ber.ReadUniversalTag(ber.TAG_OCTET_STRING, false, r) {
		return nil, errors.New("invalid expected BER tag")
	}
	dataLen, _ := ber.ReadLength(r)
	c.userData, err = core.ReadBytes(dataLen, r)
	return c, err
}

type MCSChannelInfo struct {
	ID   uint16
	Name string
}

type MCS struct {
	emission.Emitter
	transport  core.Transport
	recvOpCode MCSDomainPDU
	sendOpCode MCSDomainPDU
	channels   []MCSChannelInfo
}

func NewMCS(t core.Transport, recvOpCode MCSDomainPDU, sendOpCode MCSDomainPDU) *MCS {
	m := &MCS{
		*emission.NewEmitter(),
		t,
		recvOpCode,
		sendOpCode,
		[]MCSChannelInfo{{MCS_GLOBAL_CHANNEL, "global"}},
	}

	m.transport.On("close", func() {
		m.Emit("close")
	}).On("error", func(err error) {
		m.Emit("error", err)
	})
	return m
}

func (x *MCS) Read(b []byte) (n int, err error) {
	return x.transport.Read(b)
}

func (x *MCS) Write(b []byte) (n int, err error) {
	return x.transport.Write(b)
}

func (m *MCS) Close() error {
	return m.transport.Close()
}

type MCSClient struct {
	*MCS
	clientCoreData     *gcc.ClientCoreData
	clientNetworkData  *gcc.ClientNetworkData
	clientSecurityData *gcc.ClientSecurityData

	serverCoreData     *gcc.ServerCoreData
	serverNetworkData  *gcc.ServerNetworkData
	serverSecurityData *gcc.ServerSecurityData

	channelsConnected  int
	userId             uint16
	nbChannelRequested int
}

func NewMCSClient(t core.Transport) *MCSClient {
	c := &MCSClient{
		MCS:                NewMCS(t, SEND_DATA_INDICATION, SEND_DATA_REQUEST),
		clientCoreData:     gcc.NewClientCoreData(),
		clientNetworkData:  gcc.NewClientNetworkData(),
		clientSecurityData: gcc.NewClientSecurityData(),
		userId:             1 + MCS_USERCHANNEL_BASE,
	}
	c.transport.On("connect", c.connect)
	return c
}

func (c *MCSClient) SetClientCoreData(width, height uint16) {
	c.clientCoreData.DesktopWidth = width
	c.clientCoreData.DesktopHeight = height
}

func (c *MCSClient) connect(selectedProtocol uint32) {
	glog.Debug("mcs client on connect", selectedProtocol)
	c.clientCoreData.ServerSelectedProtocol = selectedProtocol

	// sendConnectInitial
	userDataBuff := bytes.Buffer{}
	userDataBuff.Write(c.clientCoreData.Block())
	userDataBuff.Write(c.clientNetworkData.Block())
	userDataBuff.Write(c.clientSecurityData.Block())

	ccReq := gcc.MakeConferenceCreateRequest(userDataBuff.Bytes())
	connectInitial := NewConnectInitial(ccReq)
	connectInitialBerEncoded := connectInitial.BER()

	dataBuff := &bytes.Buffer{}
	ber.WriteApplicationTag(uint8(MCS_TYPE_CONNECT_INITIAL), len(connectInitialBerEncoded), dataBuff)
	dataBuff.Write(connectInitialBerEncoded)

	_, err := c.transport.Write(dataBuff.Bytes())
	if err != nil {
		c.Emit("error", errors.New(fmt.Sprintf("mcs sendConnectInitial write error %v", err)))
		return
	}
	glog.Debug("mcs wait for data event")
	c.transport.Once("data", c.recvConnectResponse)
}

func (c *MCSClient) recvConnectResponse(s []byte) {
	glog.Debug("mcs recvConnectResponse", hex.EncodeToString(s))
	cResp, err := ReadConnectResponse(bytes.NewReader(s))
	if err != nil {
		c.Emit("error", errors.New(fmt.Sprintf("ReadConnectResponse %v", err)))
		return
	}
	// record server gcc block
	serverSettings := gcc.ReadConferenceCreateResponse(cResp.userData)

	for _, v := range serverSettings {

		switch v.(type) {
		case *gcc.ServerSecurityData:
			c.serverSecurityData = v.(*gcc.ServerSecurityData)

		case *gcc.ServerCoreData:
			c.serverCoreData = v.(*gcc.ServerCoreData)

		case *gcc.ServerNetworkData:
			c.serverNetworkData = v.(*gcc.ServerNetworkData)

		default:
			err := errors.New(fmt.Sprintf("unhandle server gcc block %v", reflect.TypeOf(v)))
			glog.Error(err)
			c.Emit("error", err)
			return
		}
	}
	glog.Debugf("serverSecurityData: %+v", c.serverSecurityData)
	glog.Debugf("serverCoreData: %+v", c.serverCoreData)
	glog.Debugf("serverNetworkData: %+v", c.serverNetworkData)
	glog.Debug("mcs sendErectDomainRequest")
	c.sendErectDomainRequest()

	glog.Debug("mcs sendAttachUserRequest")
	c.sendAttachUserRequest()

	c.transport.Once("data", c.recvAttachUserConfirm)
}

func (c *MCSClient) sendErectDomainRequest() {
	buff := &bytes.Buffer{}
	writeMCSPDUHeader(ERECT_DOMAIN_REQUEST, 0, buff)
	per.WriteInteger(0, buff)
	per.WriteInteger(0, buff)
	c.transport.Write(buff.Bytes())
}

func (c *MCSClient) sendAttachUserRequest() {
	buff := &bytes.Buffer{}
	writeMCSPDUHeader(ATTACH_USER_REQUEST, 0, buff)
	c.transport.Write(buff.Bytes())
}

func (c *MCSClient) recvAttachUserConfirm(s []byte) {
	glog.Debug("mcs recvAttachUserConfirm", hex.EncodeToString(s))
	r := bytes.NewReader(s)

	option, err := core.ReadUInt8(r)
	if err != nil {
		c.Emit("error", err)
		return
	}

	if !readMCSPDUHeader(option, ATTACH_USER_CONFIRM) {
		c.Emit("error", errors.New("NODE_RDP_PROTOCOL_T125_MCS_BAD_HEADER"))
		return
	}

	e, err := per.ReadEnumerates(r)
	if err != nil {
		c.Emit("error", err)
		return
	}
	if e != 0 {
		c.Emit("error", errors.New("NODE_RDP_PROTOCOL_T125_MCS_SERVER_REJECT_USER'"))
		return
	}

	userId, _ := per.ReadInteger16(r)
	userId += MCS_USERCHANNEL_BASE
	c.userId = userId

	c.channels = append(c.channels, MCSChannelInfo{userId, "user"})
	c.connectChannels()
}

func (c *MCSClient) connectChannels() {
	glog.Debug("mcs connectChannels:", c.channelsConnected, ":", len(c.channels))
	if c.channelsConnected == len(c.channels) {
		//if c.nbChannelRequested < int(c.serverNetworkData.ChannelCount) {
		//static virtual channel
		//chanId := c.serverNetworkData.ChannelIdArray[c.nbChannelRequested]
		//c.nbChannelRequested++
		//c.sendChannelJoinRequest(chanId)
		//return
		//}
		c.transport.On("data", c.recvData)
		// send client and sever gcc informations callback to sec
		clientData := make([]interface{}, 0)
		clientData = append(clientData, c.clientCoreData)
		clientData = append(clientData, c.clientSecurityData)
		clientData = append(clientData, c.clientNetworkData)

		serverData := make([]interface{}, 0)

		serverData = append(serverData, c.serverCoreData)
		serverData = append(serverData, c.serverSecurityData)
		glog.Debug("msc connectChannels callback to sec")
		c.Emit("connect", clientData, serverData, c.userId, c.channels)
		return
	}

	// sendChannelJoinRequest
	glog.Debug("sendChannelJoinRequest:", c.channels[c.channelsConnected].Name)
	c.sendChannelJoinRequest(c.channels[c.channelsConnected].ID)
	c.channelsConnected += 1

	c.transport.Once("data", c.recvChannelJoinConfirm)
}

func (c *MCSClient) sendChannelJoinRequest(channelId uint16) {
	glog.Debug("mcs sendChannelJoinRequest", channelId)
	buff := &bytes.Buffer{}
	writeMCSPDUHeader(CHANNEL_JOIN_REQUEST, 0, buff)
	per.WriteInteger16(c.userId-MCS_USERCHANNEL_BASE, buff)
	per.WriteInteger16(channelId, buff)
	c.transport.Write(buff.Bytes())
}

func (c *MCSClient) recvData(s []byte) {
	glog.Debug("msc on data recvData:", hex.EncodeToString(s))

	r := bytes.NewReader(s)
	option, err := core.ReadUInt8(r)
	if err != nil {
		c.Emit("error", err)
		return
	}

	if readMCSPDUHeader(option, DISCONNECT_PROVIDER_ULTIMATUM) {
		c.Emit("error", errors.New("MCS DISCONNECT_PROVIDER_ULTIMATUM"))
		c.transport.Close()
		return
	} else if !readMCSPDUHeader(option, c.recvOpCode) {
		c.Emit("error", errors.New("Invalid expected MCS opcode receive data"))
		return
	}

	userId, _ := per.ReadInteger16(r)
	userId += MCS_USERCHANNEL_BASE

	channelId, _ := per.ReadInteger16(r)
	per.ReadEnumerates(r)
	size, _ := per.ReadLength(r)

	// channel ID doesn't match a requested layer
	found := false
	channelName := ""
	for _, channel := range c.channels {
		if channel.ID == channelId {
			found = true
			channelName = channel.Name
			break
		}
	}
	if !found {
		glog.Error("mcs receive data for an unconnected layer")
		return
	}
	left, err := core.ReadBytes(int(size), r)
	if err != nil {
		c.Emit("error", errors.New(fmt.Sprintf("mcs recvData get data error %v", err)))
		return
	}
	glog.Debug("mcs emit channel", channelName, left)
	c.Emit(channelName, left)
	//c.Emit(channelName, s)
}

func (c *MCSClient) recvChannelJoinConfirm(s []byte) {
	glog.Debug("mcs recvChannelJoinConfirm", hex.EncodeToString(s))
	r := bytes.NewReader(s)
	option, err := core.ReadUInt8(r)
	if err != nil {
		c.Emit("error", err)
		return
	}

	if !readMCSPDUHeader(option, CHANNEL_JOIN_CONFIRM) {
		c.Emit("error", errors.New("NODE_RDP_PROTOCOL_T125_MCS_WAIT_CHANNEL_JOIN_CONFIRM"))
		return
	}

	confirm, _ := per.ReadEnumerates(r)
	userId, _ := per.ReadInteger16(r)
	userId += MCS_USERCHANNEL_BASE
	if c.userId != userId {
		c.Emit("error", errors.New("NODE_RDP_PROTOCOL_T125_MCS_INVALID_USER_ID"))
		return
	}

	channelId, _ := per.ReadInteger16(r)
	if (confirm != 0) && (channelId == uint16(MCS_GLOBAL_CHANNEL) || channelId == c.userId) {
		c.Emit("error", errors.New("NODE_RDP_PROTOCOL_T125_MCS_SERVER_MUST_CONFIRM_STATIC_CHANNEL"))
		return
	}

	/*if confirm == 0 {
		for i := 0; i < int(c.serverNetworkData.ChannelCount); i++ {
			if channelId == c.serverNetworkData.ChannelIdArray[i] {
				c.channels[channelId] = c.serverNetworkData.ChannelIdArray[i][1]
			}
		}
	}*/

	c.connectChannels()
}

func (c *MCSClient) SendToChannel(data []byte, channelId uint16) (n int, err error) {
	buff := &bytes.Buffer{}
	writeMCSPDUHeader(c.sendOpCode, 0, buff)
	per.WriteInteger16(c.userId-MCS_USERCHANNEL_BASE, buff)
	per.WriteInteger16(channelId, buff)
	core.WriteUInt8(0x70, buff)
	per.WriteLength(len(data), buff)
	core.WriteBytes(data, buff)
	glog.Debug("MCSClient write", hex.EncodeToString(buff.Bytes()))
	return c.transport.Write(buff.Bytes())
}

func (c *MCSClient) Write(data []byte) (n int, err error) {
	return c.SendToChannel(data, c.channels[0].ID)
}
