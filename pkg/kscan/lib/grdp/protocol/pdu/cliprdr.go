package pdu

import (
	"bytes"

	"github.com/GhostTroops/scan4all/pkg/kscan/lib/grdp/core"
	"github.com/GhostTroops/scan4all/pkg/kscan/lib/grdp/glog"
)

/**
 *                                    Initialization Sequence\n
 *     Client                                                                    Server\n
 *        |                                                                         |\n
 *        |<----------------------Server Clipboard Capabilities PDU-----------------|\n
 *        |<-----------------------------Monitor Ready PDU--------------------------|\n
 *        |-----------------------Client Clipboard Capabilities PDU---------------->|\n
 *        |---------------------------Temporary Directory PDU---------------------->|\n
 *        |-------------------------------Format List PDU-------------------------->|\n
 *        |<--------------------------Format List Response PDU----------------------|\n
 *
 */

/**
 *                                    Data Transfer Sequences\n
 *     Shared                                                                     Local\n
 *  Clipboard Owner                                                           Clipboard Owner\n
 *        |                                                                         |\n
 *        |-------------------------------------------------------------------------|\n _
 *        |-------------------------------Format List PDU-------------------------->|\n  |
 *        |<--------------------------Format List Response PDU----------------------|\n _| Copy
 * Sequence
 *        |<---------------------Lock Clipboard Data PDU (Optional)-----------------|\n
 *        |-------------------------------------------------------------------------|\n
 *        |-------------------------------------------------------------------------|\n _
 *        |<--------------------------Format Data Request PDU-----------------------|\n  | Paste
 * Sequence Palette,
 *        |---------------------------Format Data Response PDU--------------------->|\n _| Metafile,
 * File List Data
 *        |-------------------------------------------------------------------------|\n
 *        |-------------------------------------------------------------------------|\n _
 *        |<------------------------Format Contents Request PDU---------------------|\n  | Paste
 * Sequence
 *        |-------------------------Format Contents Response PDU------------------->|\n _| File
 * Stream Data
 *        |<---------------------Lock Clipboard Data PDU (Optional)-----------------|\n
 *        |-------------------------------------------------------------------------|\n
 *
 */

type MsgType uint16

const (
	CB_MONITOR_READY         = 0x0001
	CB_FORMAT_LIST           = 0x0002
	CB_FORMAT_LIST_RESPONSE  = 0x0003
	CB_FORMAT_DATA_REQUEST   = 0x0004
	CB_FORMAT_DATA_RESPONSE  = 0x0005
	CB_TEMP_DIRECTORY        = 0x0006
	CB_CLIP_CAPS             = 0x0007
	CB_FILECONTENTS_REQUEST  = 0x0008
	CB_FILECONTENTS_RESPONSE = 0x0009
	CB_LOCK_CLIPDATA         = 0x000A
	CB_UNLOCK_CLIPDATA       = 0x000B
)

type MsgFlags uint16

const (
	CB_RESPONSE_OK   = 0x0001
	CB_RESPONSE_FAIL = 0x0002
	CB_ASCII_NAMES   = 0x0004
)

type DwFlags uint32

const (
	FILECONTENTS_SIZE  = 0x00000001
	FILECONTENTS_RANGE = 0x00000002
)

type CliprdrPDUHeader struct {
	MsgType  uint16 `struc:"little"`
	MsgFlags uint16 `struc:"little"`
	DataLen  uint32 `struc:"little"`
}

func NewCliprdrPDUHeader(mType, flags uint16, ln uint32) *CliprdrPDUHeader {
	return &CliprdrPDUHeader{
		MsgType:  mType,
		MsgFlags: flags,
		DataLen:  ln,
	}
}

/*
	func (c *CliprdrPDU) serialize() []byte {
		b := &bytes.Buffer{}

		return b.Bytes()
	}

func (c *CliprdrPDU) SendCliprdrGeneralCapability() {

}
func (c *CliprdrPDU) RecvCliprdrCaps() {

}

func (c *CliprdrPDU) RecvMonitorReady() {

}

func (c *CliprdrPDU) SendCliprdrFileContentsRequest() {

}
func (c *CliprdrPDU) SendCliprdrFileContentsResponse() {

}
func (c *CliprdrPDU) SendCliprdrClientFormatList() {

}

func (c *CliprdrPDU) RecvCliprdrClientFormatListResponse() {

}
*/
type CliprdrClient struct {
	useLongFormatNames    bool
	streamFileClipEnabled bool
	fileClipNoFilePaths   bool
	canLockClipData       bool
	hasHugeFileSupport    bool
}

func process_message(s []byte) {
	r := bytes.NewReader(s)

	msgType, _ := core.ReadUint16LE(r)
	flag, _ := core.ReadUint16LE(r)
	length, _ := core.ReadUInt32LE(r)

	glog.Debug("cliprdr: type=%d flag=%d length=%d", msgType, flag, length)

	switch msgType {
	case CB_MONITOR_READY:
		//clipboard_sync(plugin->device_data);
		break
	case CB_FORMAT_LIST:
		//clipboard_format_list(plugin->device_data, flag,
		//	data + 8, length);
		//cliprdr_send_packet(plugin, CB_FORMAT_LIST_RESPONSE,
		//	CB_RESPONSE_OK, NULL, 0);
		break
	case CB_FORMAT_LIST_RESPONSE:
		//clipboard_format_list_response(plugin->device_data, flag);
		break
	case CB_FORMAT_DATA_REQUEST:
		//format = GET_UINT32(data, 8);
		//clipboard_request_data(plugin->device_data, format);
		break
	case CB_FORMAT_DATA_RESPONSE:
		//clipboard_handle_data(plugin->device_data, flag,
		//data + 8, length);
		//break;
	case CB_CLIP_CAPS:
		//clipboard_handle_caps(plugin->device_data, flag,
		//data + 8, length);
		break
	default:
		glog.Error("type %d not supported", msgType)
		break
	}

}

type CliprdrGeneralCapabilitySet struct {
	CapabilitySetType   uint16 `struc:"little"`
	CapabilitySetLength uint16 `struc:"little"`
	Version             uint32 `struc:"little"`
	GeneralFlags        uint32 `struc:"little"`
}
type CliprdrCapabilitySets struct {
	CapabilitySetType uint16 `struc:"little"`
	LengthCapability  uint16 `struc:"little,sizeof=CapabilityData"`
	CapabilityData    []byte `struc:"little"`
}
type CliprdrCapabilitiesPDU struct {
	*CliprdrPDUHeader `struc:"little"`
	CCapabilitiesSets uint16                      `struc:"little"`
	Pad1              uint16                      `struc:"little"`
	CapabilitySets    CliprdrGeneralCapabilitySet `struc:"little"`
}

type CliprdrMonitorReady struct {
	*CliprdrPDUHeader `struc:"little"`
}

type GeneralFlags uint32

const (
	/* CLIPRDR_GENERAL_CAPABILITY.generalFlags */
	CB_USE_LONG_FORMAT_NAMES     = 0x00000002
	CB_STREAM_FILECLIP_ENABLED   = 0x00000004
	CB_FILECLIP_NO_FILE_PATHS    = 0x00000008
	CB_CAN_LOCK_CLIPDATA         = 0x00000010
	CB_HUGE_FILE_SUPPORT_ENABLED = 0x00000020
)

const (
	/* CLIPRDR_GENERAL_CAPABILITY.version */
	CB_CAPS_VERSION_1 = 0x00000001
	CB_CAPS_VERSION_2 = 0x00000002
)
const (
	CB_CAPSTYPE_GENERAL_LEN = 12
)

func CliprdrInit(context CliprdrClient) {
	var (
		generalFlags         uint32
		generalCapabilitySet CliprdrGeneralCapabilitySet
		monitorReady         CliprdrMonitorReady
		capabilities         CliprdrCapabilitiesPDU
	)

	generalFlags = 0
	monitorReady.MsgType = CB_MONITOR_READY
	capabilities.MsgType = CB_CLIP_CAPS

	if context.useLongFormatNames {
		generalFlags |= CB_USE_LONG_FORMAT_NAMES
	}

	if context.streamFileClipEnabled {
		generalFlags |= CB_STREAM_FILECLIP_ENABLED
	}

	if context.fileClipNoFilePaths {
		generalFlags |= CB_FILECLIP_NO_FILE_PATHS
	}

	if context.canLockClipData {
		generalFlags |= CB_CAN_LOCK_CLIPDATA
	}

	if context.hasHugeFileSupport {
		generalFlags |= CB_HUGE_FILE_SUPPORT_ENABLED
	}

	capabilities.MsgType = CB_CLIP_CAPS
	capabilities.MsgFlags = 0
	capabilities.DataLen = 4 + CB_CAPSTYPE_GENERAL_LEN
	capabilities.CCapabilitiesSets = 1

	generalCapabilitySet.CapabilitySetType = 0x0001
	generalCapabilitySet.CapabilitySetLength = CB_CAPSTYPE_GENERAL_LEN
	generalCapabilitySet.Version = CB_CAPS_VERSION_2
	generalCapabilitySet.GeneralFlags = generalFlags
	capabilities.CapabilitySets = generalCapabilitySet

	/*	if ((err= context->ServerCapabilities(context, &capabilities))){
			//glog.Error(TAG, "ServerCapabilities failed with error %" PRIu32 "!", err);
			return err
		}

		if ((err = context->MonitorReady(context, &monitorReady))){
			//glog.Error("MonitorReady failed with error %" PRIu32 "!", err);
			return err
		}*/

	//return err
}

// temp dir
type CliprdrTempDirectory struct {
	Header    *CliprdrPDUHeader
	SzTempDir string
}

// format list
type CliprdrFormat struct {
	FormatId   uint32
	FormatName string
}
type CliprdrFormatList struct {
	Header     *CliprdrPDUHeader
	NumFormats uint32
	Formats    []CliprdrFormat
}
type ClipboardFormats uint16

const (
	CB_FORMAT_HTML             = 0xD010
	CB_FORMAT_PNG              = 0xD011
	CB_FORMAT_JPEG             = 0xD012
	CB_FORMAT_GIF              = 0xD013
	CB_FORMAT_TEXTURILIST      = 0xD014
	CB_FORMAT_GNOMECOPIEDFILES = 0xD015
	CB_FORMAT_MATECOPIEDFILES  = 0xD016
)

// lock or unlock
type CliprdrCtrlClipboardData struct {
	Header     *CliprdrPDUHeader
	ClipDataId uint32
}

// format data
type CliprdrFormatDataRequest struct {
	Header            *CliprdrPDUHeader
	RequestedFormatId uint32
}
type CliprdrFormatDataResponse struct {
	Header              *CliprdrPDUHeader
	RequestedFormatData []byte
}

// file contents
type CliprdrFileContentsRequest struct {
	Header        *CliprdrPDUHeader
	StreamId      uint32
	Lindex        int32
	DwFlags       uint32
	NPositionLow  uint32
	NPositionHigh uint32
	CbRequested   uint32
	ClipDataId    uint32
}

func NewCliprdrFileContentsRequest() *CliprdrFileContentsRequest {
	return &CliprdrFileContentsRequest{
		Header: NewCliprdrPDUHeader(CB_FILECONTENTS_REQUEST, 0, 0),
	}
}

type CliprdrFileContentsResponse struct {
	Header        *CliprdrPDUHeader
	StreamId      uint32
	CbRequested   uint32
	RequestedData []byte
}
