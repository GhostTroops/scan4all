package pdu

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/GhostTroops/scan4all/pkg/kscan/lib/grdp/core"
	"github.com/GhostTroops/scan4all/pkg/kscan/lib/grdp/glog"
	"github.com/lunixbochs/struc"
)

const (
	PDUTYPE_DEMANDACTIVEPDU  = 0x11
	PDUTYPE_CONFIRMACTIVEPDU = 0x13
	PDUTYPE_DEACTIVATEALLPDU = 0x16
	PDUTYPE_DATAPDU          = 0x17
	PDUTYPE_SERVER_REDIR_PKT = 0x1A
)

const (
	PDUTYPE2_UPDATE                      = 0x02
	PDUTYPE2_CONTROL                     = 0x14
	PDUTYPE2_POINTER                     = 0x1B
	PDUTYPE2_INPUT                       = 0x1C
	PDUTYPE2_SYNCHRONIZE                 = 0x1F
	PDUTYPE2_REFRESH_RECT                = 0x21
	PDUTYPE2_PLAY_SOUND                  = 0x22
	PDUTYPE2_SUPPRESS_OUTPUT             = 0x23
	PDUTYPE2_SHUTDOWN_REQUEST            = 0x24
	PDUTYPE2_SHUTDOWN_DENIED             = 0x25
	PDUTYPE2_SAVE_SESSION_INFO           = 0x26
	PDUTYPE2_FONTLIST                    = 0x27
	PDUTYPE2_FONTMAP                     = 0x28
	PDUTYPE2_SET_KEYBOARD_INDICATORS     = 0x29
	PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST = 0x2B
	PDUTYPE2_BITMAPCACHE_ERROR_PDU       = 0x2C
	PDUTYPE2_SET_KEYBOARD_IME_STATUS     = 0x2D
	PDUTYPE2_OFFSCRCACHE_ERROR_PDU       = 0x2E
	PDUTYPE2_SET_ERROR_INFO_PDU          = 0x2F
	PDUTYPE2_DRAWNINEGRID_ERROR_PDU      = 0x30
	PDUTYPE2_DRAWGDIPLUS_ERROR_PDU       = 0x31
	PDUTYPE2_ARC_STATUS_PDU              = 0x32
	PDUTYPE2_STATUS_INFO_PDU             = 0x36
	PDUTYPE2_MONITOR_LAYOUT_PDU          = 0x37
)

const (
	CTRLACTION_REQUEST_CONTROL = 0x0001
	CTRLACTION_GRANTED_CONTROL = 0x0002
	CTRLACTION_DETACH          = 0x0003
	CTRLACTION_COOPERATE       = 0x0004
)

const (
	STREAM_UNDEFINED = 0x00
	STREAM_LOW       = 0x01
	STREAM_MED       = 0x02
	STREAM_HI        = 0x04
)

const (
	FASTPATH_UPDATETYPE_ORDERS       = 0x0
	FASTPATH_UPDATETYPE_BITMAP       = 0x1
	FASTPATH_UPDATETYPE_PALETTE      = 0x2
	FASTPATH_UPDATETYPE_SYNCHRONIZE  = 0x3
	FASTPATH_UPDATETYPE_SURFCMDS     = 0x4
	FASTPATH_UPDATETYPE_PTR_NULL     = 0x5
	FASTPATH_UPDATETYPE_PTR_DEFAULT  = 0x6
	FASTPATH_UPDATETYPE_PTR_POSITION = 0x8
	FASTPATH_UPDATETYPE_COLOR        = 0x9
	FASTPATH_UPDATETYPE_CACHED       = 0xA
	FASTPATH_UPDATETYPE_POINTER      = 0xB
)

const (
	BITMAP_COMPRESSION = 0x0001
	//NO_BITMAP_COMPRESSION_HDR = 0x0400
)

type ShareDataHeader struct {
	SharedId           uint32 `struc:"little"`
	Padding1           uint8  `struc:"little"`
	StreamId           uint8  `struc:"little"`
	UncompressedLength uint16 `struc:"little"`
	PDUType2           uint8  `struc:"little"`
	CompressedType     uint8  `struc:"little"`
	CompressedLength   uint16 `struc:"little"`
}

func NewShareDataHeader(size int, type2 uint8, shareId uint32) *ShareDataHeader {
	return &ShareDataHeader{
		SharedId:           shareId,
		PDUType2:           type2,
		StreamId:           STREAM_LOW,
		UncompressedLength: uint16(size + 4),
	}
}

type PDUMessage interface {
	Type() uint16
	Serialize() []byte
}

type DemandActivePDU struct {
	SharedId                   uint32       `struc:"little"`
	LengthSourceDescriptor     uint16       `struc:"little,sizeof=SourceDescriptor"`
	LengthCombinedCapabilities uint16       `struc:"little"`
	SourceDescriptor           []byte       `struc:"sizefrom=LengthSourceDescriptor"`
	NumberCapabilities         uint16       `struc:"little,sizeof=CapabilitySets"`
	Pad2Octets                 uint16       `struc:"little"`
	CapabilitySets             []Capability `struc:"sizefrom=NumberCapabilities"`
	SessionId                  uint32       `struc:"little"`
}

func (d *DemandActivePDU) Type() uint16 {
	return PDUTYPE_DEMANDACTIVEPDU
}

func (d *DemandActivePDU) Serialize() []byte {
	buff := &bytes.Buffer{}
	core.WriteUInt32LE(d.SharedId, buff)
	core.WriteUInt16LE(d.LengthSourceDescriptor, buff)
	core.WriteUInt16LE(d.LengthCombinedCapabilities, buff)
	core.WriteBytes([]byte(d.SourceDescriptor), buff)
	core.WriteUInt16LE(uint16(len(d.CapabilitySets)), buff)
	core.WriteUInt16LE(d.Pad2Octets, buff)
	for _, cap := range d.CapabilitySets {
		core.WriteUInt16LE(uint16(cap.Type()), buff)
		capBuff := &bytes.Buffer{}
		struc.Pack(capBuff, cap)
		capBytes := capBuff.Bytes()
		core.WriteUInt16LE(uint16(len(capBytes)+4), buff)
		core.WriteBytes(capBytes, buff)
	}
	core.WriteUInt32LE(d.SessionId, buff)
	return buff.Bytes()
}

func readDemandActivePDU(r io.Reader) (*DemandActivePDU, error) {
	d := &DemandActivePDU{}
	var err error
	d.SharedId, err = core.ReadUInt32LE(r)
	if err != nil {
		return nil, err
	}
	d.LengthSourceDescriptor, err = core.ReadUint16LE(r)
	d.LengthCombinedCapabilities, err = core.ReadUint16LE(r)
	sourceDescriptorBytes, err := core.ReadBytes(int(d.LengthSourceDescriptor), r)
	if err != nil {
		return nil, err
	}
	d.SourceDescriptor = sourceDescriptorBytes
	d.NumberCapabilities, err = core.ReadUint16LE(r)
	d.Pad2Octets, err = core.ReadUint16LE(r)
	d.CapabilitySets = make([]Capability, 0)
	glog.Debug("NumberCapabilities is", d.NumberCapabilities)
	for i := 0; i < int(d.NumberCapabilities); i++ {
		c, err := readCapability(r)
		if err != nil {
			//return nil, err
			continue
		}
		d.CapabilitySets = append(d.CapabilitySets, c)
	}
	d.NumberCapabilities = uint16(len(d.CapabilitySets))
	d.SessionId, err = core.ReadUInt32LE(r)
	//glog.Info("SessionId:", d.SessionId)
	if err != nil {
		return nil, err
	}
	return d, nil
}

type ConfirmActivePDU struct {
	SharedId                   uint32       `struc:"little"`
	OriginatorId               uint16       `struc:"little"`
	LengthSourceDescriptor     uint16       `struc:"little,sizeof=SourceDescriptor"`
	LengthCombinedCapabilities uint16       `struc:"little"`
	SourceDescriptor           []byte       `struc:"sizefrom=LengthSourceDescriptor"`
	NumberCapabilities         uint16       `struc:"little,sizeof=CapabilitySets"`
	Pad2Octets                 uint16       `struc:"little"`
	CapabilitySets             []Capability `struc:"sizefrom=NumberCapabilities"`
}

func (*ConfirmActivePDU) Type() uint16 {
	return PDUTYPE_CONFIRMACTIVEPDU
}

func (c *ConfirmActivePDU) Serialize() []byte {
	buff := &bytes.Buffer{}
	core.WriteUInt32LE(c.SharedId, buff)
	core.WriteUInt16LE(c.OriginatorId, buff)
	core.WriteUInt16LE(uint16(len(c.SourceDescriptor)), buff)

	capsBuff := &bytes.Buffer{}
	for _, capa := range c.CapabilitySets {
		core.WriteUInt16LE(uint16(capa.Type()), capsBuff)
		capBuff := &bytes.Buffer{}
		struc.Pack(capBuff, capa)
		if capa.Type() == CAPSTYPE_INPUT {
			core.WriteBytes([]byte{0x0c, 0x00, 0x00, 0x00}, capBuff)
		}
		capBytes := capBuff.Bytes()
		core.WriteUInt16LE(uint16(len(capBytes)+4), capsBuff)
		core.WriteBytes(capBytes, capsBuff)
	}
	capsBytes := capsBuff.Bytes()

	core.WriteUInt16LE(uint16(2+2+len(capsBytes)), buff)
	core.WriteBytes([]byte(c.SourceDescriptor), buff)
	core.WriteUInt16LE(uint16(len(c.CapabilitySets)), buff)
	core.WriteUInt16LE(c.Pad2Octets, buff)
	core.WriteBytes(capsBytes, buff)
	return buff.Bytes()
}

// 9401 => share control header
// 1300 => share control header
// ec03 => share control header
// ea030100  => shareId 66538
// ea03 => OriginatorId
// 0400
// 8001 => LengthCombinedCapabilities
// 72647079
// 0c00 => NumberCapabilities 12
// 0000
// caps below
// 010018000100030000020000000015040000000000000000
// 02001c00180001000100010000052003000000000100000001000000
// 030058000000000000000000000000000000000000000000010014000000010000000a0000000000000000000000000000000000000000000000000000000000000000000000000000000000008403000000000000000000
// 04002800000000000000000000000000000000000000000000000000000000000000000000000000
// 0800080000001400
// 0c00080000000000
// 0d005c001500000009040000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000
// 0f00080000000000
// 10003400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
// 11000c000000000000000000
// 14000c000000000000000000
// 1a00080000000000

func NewConfirmActivePDU() *ConfirmActivePDU {
	return &ConfirmActivePDU{
		OriginatorId:     0x03EA,
		CapabilitySets:   make([]Capability, 0),
		SourceDescriptor: []byte("rdpy"),
	}
}

func readConfirmActivePDU(r io.Reader) (*ConfirmActivePDU, error) {
	p := &ConfirmActivePDU{}
	var err error
	p.SharedId, err = core.ReadUInt32LE(r)
	if err != nil {
		return nil, err
	}
	p.OriginatorId, err = core.ReadUint16LE(r)
	p.LengthSourceDescriptor, err = core.ReadUint16LE(r)
	p.LengthCombinedCapabilities, err = core.ReadUint16LE(r)

	sourceDescriptorBytes, err := core.ReadBytes(int(p.LengthSourceDescriptor), r)
	if err != nil {
		return nil, err
	}
	p.SourceDescriptor = sourceDescriptorBytes
	p.NumberCapabilities, err = core.ReadUint16LE(r)
	p.Pad2Octets, err = core.ReadUint16LE(r)

	p.CapabilitySets = make([]Capability, 0)
	for i := 0; i < int(p.NumberCapabilities); i++ {
		c, err := readCapability(r)
		if err != nil {
			return nil, err
		}
		p.CapabilitySets = append(p.CapabilitySets, c)
	}
	s, _ := core.ReadUInt32LE(r)
	glog.Info("sessionid:", s)
	return p, nil
}

type DeactiveAllPDU struct {
	ShareId                uint32 `struc:"little"`
	LengthSourceDescriptor uint16 `struc:"little,sizeof=SourceDescriptor"`
	SourceDescriptor       []byte
}

func (*DeactiveAllPDU) Type() uint16 {
	return PDUTYPE_DEACTIVATEALLPDU
}

func (d *DeactiveAllPDU) Serialize() []byte {
	buff := &bytes.Buffer{}
	struc.Pack(buff, d)
	return buff.Bytes()
}

func readDeactiveAllPDU(r io.Reader) (*DeactiveAllPDU, error) {
	p := &DeactiveAllPDU{}
	err := struc.Unpack(r, p)
	return p, err
}

type DataPDU struct {
	Header *ShareDataHeader
	Data   DataPDUData
}

func (*DataPDU) Type() uint16 {
	return PDUTYPE_DATAPDU
}

func (d *DataPDU) Serialize() []byte {
	buff := &bytes.Buffer{}
	struc.Pack(buff, d.Header)
	struc.Pack(buff, d.Data)
	return buff.Bytes()
}

func NewDataPDU(data DataPDUData, shareId uint32) *DataPDU {
	dataBuff := &bytes.Buffer{}
	struc.Pack(dataBuff, data)
	return &DataPDU{
		Header: NewShareDataHeader(len(dataBuff.Bytes()), data.Type2(), shareId),
		Data:   data,
	}
}

func readDataPDU(r io.Reader) (*DataPDU, error) {
	header := &ShareDataHeader{}
	err := struc.Unpack(r, header)
	if err != nil {
		glog.Error("read data pdu header error", err)
		return nil, err
	}
	var d DataPDUData
	glog.Debugf("header=%02x", header.PDUType2)
	switch header.PDUType2 {
	case PDUTYPE2_SYNCHRONIZE:
		d = &SynchronizeDataPDU{}
	case PDUTYPE2_CONTROL:
		d = &ControlDataPDU{}
	case PDUTYPE2_FONTLIST:
		d = &FontListDataPDU{}
	case PDUTYPE2_SET_ERROR_INFO_PDU:
		d = &ErrorInfoDataPDU{}
	case PDUTYPE2_FONTMAP:
		d = &FontMapDataPDU{}
	case PDUTYPE2_SAVE_SESSION_INFO:
		s := &SaveSessionInfo{}
		s.Unpack(r)
		d = s
	default:
		err = errors.New(fmt.Sprintf("Unknown data pdu type2 0x%02x", header.PDUType2))
		glog.Error(err)
		return nil, err
	}

	if header.PDUType2 != PDUTYPE2_SAVE_SESSION_INFO {
		err = struc.Unpack(r, d)
		if err != nil {
			glog.Error("read data pdu error", err)
			return nil, err
		}
	}

	glog.Debugf("d=%+v", d)
	p := &DataPDU{
		Header: header,
		Data:   d,
	}
	return p, nil
}

type DataPDUData interface {
	Type2() uint8
}

type SynchronizeDataPDU struct {
	MessageType uint16 `struc:"little"`
	TargetUser  uint16 `struc:"little"`
}

func (*SynchronizeDataPDU) Type2() uint8 {
	return PDUTYPE2_SYNCHRONIZE
}

func NewSynchronizeDataPDU(targetUser uint16) *SynchronizeDataPDU {
	return &SynchronizeDataPDU{
		MessageType: 1,
		TargetUser:  targetUser,
	}
}

type ControlDataPDU struct {
	Action    uint16 `struc:"little"`
	GrantId   uint16 `struc:"little"`
	ControlId uint32 `struc:"little"`
}

func (*ControlDataPDU) Type2() uint8 {
	return PDUTYPE2_CONTROL
}

type FontListDataPDU struct {
	NumberFonts   uint16 `struc:"little"`
	TotalNumFonts uint16 `struc:"little"`
	ListFlags     uint16 `struc:"little"`
	EntrySize     uint16 `struc:"little"`
}

func (*FontListDataPDU) Type2() uint8 {
	return PDUTYPE2_FONTLIST
}

type ErrorInfoDataPDU struct {
	ErrorInfo uint32 `struc:"little"`
}

func (*ErrorInfoDataPDU) Type2() uint8 {
	return PDUTYPE2_SET_ERROR_INFO_PDU
}

type FontMapDataPDU struct {
	NumberEntries   uint16 `struc:"little"`
	TotalNumEntries uint16 `struc:"little"`
	MapFlags        uint16 `struc:"little"`
	EntrySize       uint16 `struc:"little"`
}

func (*FontMapDataPDU) Type2() uint8 {
	return PDUTYPE2_FONTMAP
}

type InfoType uint32

const (
	INFOTYPE_LOGON               = 0x00000000
	INFOTYPE_LOGON_LONG          = 0x00000001
	INFOTYPE_LOGON_PLAINNOTIFY   = 0x00000002
	INFOTYPE_LOGON_EXTENDED_INFO = 0x00000003
)
const (
	LOGON_EX_AUTORECONNECTCOOKIE = 0x00000001
	LOGON_EX_LOGONERRORS         = 0x00000002
)

type LogonFields struct {
	CbFileData uint32   `struc:"little"`
	Len        uint32   //28 `struc:"little"`
	Version    uint32   // 1 `struc:"little"`
	LogonId    uint32   `struc:"little"`
	random     [16]byte //16 `struc:"little"`
}
type SaveSessionInfo struct {
	InfoType      uint32
	Length        uint16
	FieldsPresent uint32
	LogonId       uint32
	Random        []byte
}

func (s *SaveSessionInfo) logonInfoV1(r io.Reader) (err error) {
	core.ReadUInt32LE(r) // cbDomain
	b, _ := core.ReadBytes(52, r)
	domain := core.UnicodeDecode(b)

	core.ReadUInt32LE(r) // cbUserName
	b, _ = core.ReadBytes(512, r)
	userName := core.UnicodeDecode(b)

	sessionId, _ := core.ReadUInt32LE(r)
	s.LogonId = sessionId
	glog.Infof("SessionId:[%d] UserName:[%s] Domain:[%s]", s.LogonId, userName, domain)
	return err
}
func (s *SaveSessionInfo) logonInfoV2(r io.Reader) (err error) {
	core.ReadUint16LE(r)
	core.ReadUInt32LE(r)
	sessionId, _ := core.ReadUInt32LE(r)
	s.LogonId = sessionId
	cbDomain, _ := core.ReadUInt32LE(r)
	cbUserName, _ := core.ReadUInt32LE(r)
	core.ReadBytes(558, r)

	b, _ := core.ReadBytes(int(cbDomain), r)
	domain := core.UnicodeDecode(b)
	b, _ = core.ReadBytes(int(cbUserName), r)
	userName := core.UnicodeDecode(b)
	glog.Infof("SessionId:[%d] UserName:[%s] Domain:[%s]", s.LogonId, userName, domain)

	return err
}
func (s *SaveSessionInfo) logonPlainNotify(r io.Reader) (err error) {
	core.ReadBytes(576, r) /* pad (576 bytes) */
	return err
}
func (s *SaveSessionInfo) logonInfoExtended(r io.Reader) (err error) {
	s.Length, err = core.ReadUint16LE(r)
	s.FieldsPresent, err = core.ReadUInt32LE(r)
	glog.Info("FieldsPresent:", s.FieldsPresent)
	// auto reconnect cookie
	if s.FieldsPresent&LOGON_EX_AUTORECONNECTCOOKIE != 0 {
		core.ReadUInt32LE(r)
		b, _ := core.ReadUInt32LE(r)
		if b != 28 {
			return errors.New(fmt.Sprintf("invalid length in Auto-Reconnect packet"))
		}
		b, _ = core.ReadUInt32LE(r)
		if b != 1 {
			return errors.New(fmt.Sprintf("unsupported version of Auto-Reconnect packet"))
		}
		b, _ = core.ReadUInt32LE(r)
		s.LogonId = b
		s.Random, _ = core.ReadBytes(16, r)
	} else { // logon error info
		core.ReadUInt32LE(r)
		b, _ := core.ReadUInt32LE(r)
		b, _ = core.ReadUInt32LE(r)
		s.LogonId = b
	}
	core.ReadBytes(570, r)
	return err
}
func (s *SaveSessionInfo) Unpack(r io.Reader) (err error) {
	s.InfoType, err = core.ReadUInt32LE(r)
	switch s.InfoType {
	case INFOTYPE_LOGON:
		err = s.logonInfoV1(r)
	case INFOTYPE_LOGON_LONG:
		err = s.logonInfoV2(r)
	case INFOTYPE_LOGON_PLAINNOTIFY:
		err = s.logonPlainNotify(r)
	case INFOTYPE_LOGON_EXTENDED_INFO:
		err = s.logonInfoExtended(r)
	default:
		glog.Error("Unhandled saveSessionInfo type 0x%", s.InfoType)
		return fmt.Errorf("Unhandled saveSessionInfo type 0x%", s.InfoType)
	}

	return err
}

func (*SaveSessionInfo) Type2() uint8 {
	return PDUTYPE2_SAVE_SESSION_INFO
}

type PersistKeyPDU struct {
	NumEntriesCache0   uint16 `struc:"little"`
	NumEntriesCache1   uint16 `struc:"little"`
	NumEntriesCache2   uint16 `struc:"little"`
	NumEntriesCache3   uint16 `struc:"little"`
	NumEntriesCache4   uint16 `struc:"little"`
	TotalEntriesCache0 uint16 `struc:"little"`
	TotalEntriesCache1 uint16 `struc:"little"`
	TotalEntriesCache2 uint16 `struc:"little"`
	TotalEntriesCache3 uint16 `struc:"little"`
	TotalEntriesCache4 uint16 `struc:"little"`
	BBitMask           uint8  `struc:"little"`
	Pad1               uint8  `struc:"little"`
	Ppad3              uint16 `struc:"little"`
}

func (*PersistKeyPDU) Type2() uint8 {
	return PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST
}

type UpdateData interface {
	FastPathUpdateType() uint8
	Unpack(io.Reader) error
}

type BitmapCompressedDataHeader struct {
	CbCompFirstRowSize uint16 `struc:"little"`
	CbCompMainBodySize uint16 `struc:"little"`
	CbScanWidth        uint16 `struc:"little"`
	CbUncompressedSize uint16 `struc:"little"`
}

type BitmapData struct {
	DestLeft         uint16 `struc:"little"`
	DestTop          uint16 `struc:"little"`
	DestRight        uint16 `struc:"little"`
	DestBottom       uint16 `struc:"little"`
	Width            uint16 `struc:"little"`
	Height           uint16 `struc:"little"`
	BitsPerPixel     uint16 `struc:"little"`
	Flags            uint16 `struc:"little"`
	BitmapLength     uint16 `struc:"little,sizeof=BitmapDataStream"`
	BitmapComprHdr   *BitmapCompressedDataHeader
	BitmapDataStream []byte
}

func (b *BitmapData) IsCompress() bool {
	return b.Flags&BITMAP_COMPRESSION != 0
}

type FastPathBitmapUpdateDataPDU struct {
	Header           uint16 `struc:"little"`
	NumberRectangles uint16 `struc:"little,sizeof=Rectangles"`
	Rectangles       []BitmapData
}

func (f *FastPathBitmapUpdateDataPDU) Unpack(r io.Reader) error {
	var err error
	f.Header, err = core.ReadUint16LE(r)
	f.NumberRectangles, err = core.ReadUint16LE(r)
	f.Rectangles = make([]BitmapData, 0, f.NumberRectangles)
	for i := 0; i < int(f.NumberRectangles); i++ {
		rect := BitmapData{}
		rect.DestLeft, err = core.ReadUint16LE(r)
		rect.DestTop, err = core.ReadUint16LE(r)
		rect.DestRight, err = core.ReadUint16LE(r)
		rect.DestBottom, err = core.ReadUint16LE(r)
		rect.Width, err = core.ReadUint16LE(r)
		rect.Height, err = core.ReadUint16LE(r)
		rect.BitsPerPixel, err = core.ReadUint16LE(r)
		rect.Flags, err = core.ReadUint16LE(r)
		rect.BitmapLength, err = core.ReadUint16LE(r)
		ln := rect.BitmapLength
		if rect.Flags&BITMAP_COMPRESSION != 0 && (rect.Flags&NO_BITMAP_COMPRESSION_HDR == 0) {
			rect.BitmapComprHdr = new(BitmapCompressedDataHeader)
			rect.BitmapComprHdr.CbCompFirstRowSize, err = core.ReadUint16LE(r)
			rect.BitmapComprHdr.CbCompMainBodySize, err = core.ReadUint16LE(r)
			rect.BitmapComprHdr.CbScanWidth, err = core.ReadUint16LE(r)
			rect.BitmapComprHdr.CbUncompressedSize, err = core.ReadUint16LE(r)
			ln = rect.BitmapComprHdr.CbCompMainBodySize
		}

		rect.BitmapDataStream, err = core.ReadBytes(int(ln), r)
		f.Rectangles = append(f.Rectangles, rect)
	}
	return err
}

func (*FastPathBitmapUpdateDataPDU) FastPathUpdateType() uint8 {
	return FASTPATH_UPDATETYPE_BITMAP
}

type FastPathUpdatePDU struct {
	UpdateHeader     uint8
	CompressionFlags uint8
	Size             uint16
	Data             UpdateData
}

const (
	FASTPATH_OUTPUT_COMPRESSION_USED = 0x2
)

func readFastPathUpdatePDU(r io.Reader) (*FastPathUpdatePDU, error) {
	f := &FastPathUpdatePDU{}
	var err error
	f.UpdateHeader, err = core.ReadUInt8(r)
	if err != nil {
		return nil, err
	}
	if (f.UpdateHeader>>4)&FASTPATH_OUTPUT_COMPRESSION_USED != 0 {
		f.CompressionFlags, err = core.ReadUInt8(r)
	}

	f.Size, err = core.ReadUint16LE(r)
	if err != nil {
		return nil, err
	}
	if f.Size == 0 {
		return f, nil
	}
	dataBytes, err := core.ReadBytes(int(f.Size), r)
	if err != nil {
		glog.Info(err)
		return nil, err
	}

	var d UpdateData
	switch f.UpdateHeader & 0xf {
	case FASTPATH_UPDATETYPE_BITMAP:
		d = &FastPathBitmapUpdateDataPDU{}

	default:
		glog.Debugf("Unknown Fast Path PDU type 0x%x", f.UpdateHeader)
		return f, errors.New(fmt.Sprintf("Unknown Fast Path PDU type 0x%x", f.UpdateHeader))
		//d = nil
	}
	if d != nil {
		err = d.Unpack(bytes.NewReader(dataBytes))
		if err != nil {
			glog.Error("Unpack:", err)
			return nil, err
		}
	}

	f.Data = d
	return f, nil
}

type ShareControlHeader struct {
	TotalLength uint16 `struc:"little"`
	PDUType     uint16 `struc:"little"`
	PDUSource   uint16 `struc:"little"`
}

type PDU struct {
	ShareCtrlHeader *ShareControlHeader
	Message         PDUMessage
}

func NewPDU(userId uint16, message PDUMessage) *PDU {
	pdu := &PDU{}
	pdu.ShareCtrlHeader = &ShareControlHeader{
		TotalLength: uint16(len(message.Serialize()) + 6),
		PDUType:     message.Type(),
		PDUSource:   userId,
	}
	pdu.Message = message
	return pdu
}

func readPDU(r io.Reader) (*PDU, error) {
	pdu := &PDU{}
	var err error
	header := &ShareControlHeader{}
	err = struc.Unpack(r, header)
	if err != nil {
		return nil, err
	}

	pdu.ShareCtrlHeader = header

	var d PDUMessage
	switch pdu.ShareCtrlHeader.PDUType {
	case PDUTYPE_DEMANDACTIVEPDU:
		glog.Debug("PDUTYPE_DEMANDACTIVEPDU")
		d, err = readDemandActivePDU(r)
	case PDUTYPE_DATAPDU:
		glog.Debug("PDUTYPE_DATAPDU")
		d, err = readDataPDU(r)
	case PDUTYPE_CONFIRMACTIVEPDU:
		glog.Debug("PDUTYPE_CONFIRMACTIVEPDU")
		d, err = readConfirmActivePDU(r)
	case PDUTYPE_DEACTIVATEALLPDU:
		glog.Debug("PDUTYPE_DEACTIVATEALLPDU")
		d, err = readDeactiveAllPDU(r)
	default:
		glog.Errorf("PDU invalid pdu type: 0x%02x", pdu.ShareCtrlHeader.PDUType)
	}
	if err != nil {
		return nil, err
	}
	pdu.Message = d
	return pdu, err
}

func (p *PDU) serialize() []byte {
	buff := &bytes.Buffer{}
	struc.Pack(buff, p.ShareCtrlHeader)
	core.WriteBytes(p.Message.Serialize(), buff)
	return buff.Bytes()
}

type SlowPathInputEvent struct {
	EventTime         uint32 `struc:"little"`
	MessageType       uint16 `struc:"little"`
	Size              int    `struc:"skip"`
	SlowPathInputData []byte `struc:"sizefrom=Size"`
}

type PointerEvent struct {
	PointerFlags uint16 `struc:"little"`
	XPos         uint16 `struc:"little"`
	YPos         uint16 `struc:"little"`
}

func (p *PointerEvent) Serialize() []byte {
	buff := &bytes.Buffer{}
	struc.Pack(buff, p)
	return buff.Bytes()
}

type SynchronizeEvent struct {
	Pad2Octets  uint16 `struc:"little"`
	ToggleFlags uint32 `struc:"little"`
}

func (p *SynchronizeEvent) Serialize() []byte {
	buff := &bytes.Buffer{}
	struc.Pack(buff, p)
	return buff.Bytes()
}

type ScancodeKeyEvent struct {
	KeyboardFlags uint16 `struc:"little"`
	KeyCode       uint16 `struc:"little"`
	Pad2Octets    uint16 `struc:"little"`
}

func (p *ScancodeKeyEvent) Serialize() []byte {
	buff := &bytes.Buffer{}
	struc.Pack(buff, p)
	return buff.Bytes()
}

type UnicodeKeyEvent struct {
	KeyboardFlags uint16 `struc:"little"`
	Unicode       uint16 `struc:"little"`
	Pad2Octets    uint16 `struc:"little"`
}

func (p *UnicodeKeyEvent) Serialize() []byte {
	buff := &bytes.Buffer{}
	struc.Pack(buff, p)
	return buff.Bytes()
}

type ClientInputEventPDU struct {
	NumEvents           uint16               `struc:"little,sizeof=SlowPathInputEvents"`
	Pad2Octets          uint16               `struc:"little"`
	SlowPathInputEvents []SlowPathInputEvent `struc:"little"`
}

func (*ClientInputEventPDU) Type2() uint8 {
	return PDUTYPE2_INPUT
}
