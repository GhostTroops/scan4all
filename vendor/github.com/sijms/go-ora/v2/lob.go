package go_ora

import (
	"bytes"
	"errors"
	"github.com/sijms/go-ora/v2/converters"
	"go/types"
)

type Clob struct {
	locator []byte
	String  string
	Valid   bool
}

type NClob Clob

type lobInterface interface {
	getLocator() []byte
}

type Blob struct {
	locator []byte
	Data    []byte
	Valid   bool
}

type Lob struct {
	connection    *Connection
	sourceLocator []byte
	destLocator   []byte
	scn           []byte
	sourceOffset  int64
	destOffset    int64
	sourceLen     int
	destLen       int
	charsetID     int
	size          int64
	data          bytes.Buffer
	bNullO2U      bool
	isNull        bool
	sendSize      bool
}

func newLob(connection *Connection) *Lob {
	return &Lob{
		connection: connection,
	}
}
func (lob *Lob) initialize() {
	lob.bNullO2U = false
	lob.sendSize = false
	lob.size = 0
	//lob.charsetID = 0
	lob.sourceOffset = 0
	lob.destOffset = 0
	//lob.scn = nil
}

// variableWidthChar if lob has variable width char or not
func (lob *Lob) variableWidthChar() bool {
	return len(lob.sourceLocator) > 6 && lob.sourceLocator[6]&128 == 128
}

// littleEndianClob if CLOB is littleEndian or not
func (lob *Lob) littleEndianClob() bool {
	return len(lob.sourceLocator) > 7 && lob.sourceLocator[7]&64 > 0
}

// getSize return lob size
func (lob *Lob) getSize() (size int64, err error) {
	lob.initialize()
	lob.sendSize = true
	session := lob.connection.session
	lob.connection.connOption.Tracer.Print("Read Lob Size")
	session.ResetBuffer()
	lob.writeOp(1)
	err = session.Write()
	if err != nil {
		return
	}
	err = lob.read()
	if err != nil {
		return
	}
	size = lob.size
	lob.connection.connOption.Tracer.Print("Lob Size: ", size)
	return
}

func (lob *Lob) getDataWithOffsetSize(offset, count int64) (data []byte, err error) {
	if offset == 0 && count == 0 {
		lob.connection.connOption.Tracer.Print("Read Lob Data:")
	} else {
		lob.connection.connOption.Tracer.Printf("Read Lob Data Position: %d, Count: %d\n", offset, count)
	}
	lob.initialize()
	lob.size = count
	lob.sourceOffset = offset + 1
	lob.sendSize = true
	lob.data.Reset()
	session := lob.connection.session
	session.ResetBuffer()
	lob.writeOp(2)
	err = session.Write()
	if err != nil {
		return
	}
	err = lob.read()
	if err != nil {
		return
	}
	data = lob.data.Bytes()
	return
}

// getData return lob data
func (lob *Lob) getData() (data []byte, err error) {
	return lob.getDataWithOffsetSize(0, 0)
}

func (lob *Lob) putData(data []byte) error {
	lob.connection.connOption.Tracer.Printf("Put Lob Data: %d bytes", len(data))
	lob.initialize()
	lob.size = int64(len(data))
	lob.sendSize = true
	lob.sourceOffset = 1
	lob.connection.session.ResetBuffer()
	lob.writeOp(0x40)
	lob.connection.session.PutBytes(0xE)
	lob.connection.session.PutClr(data)
	err := lob.connection.session.Write()
	if err != nil {
		return err
	}
	return lob.read()
}

func (lob *Lob) putString(data string) error {
	conn := lob.connection
	conn.connOption.Tracer.Printf("Put Lob String: %d character", int64(len([]rune(data))))
	lob.initialize()
	var strConv converters.IStringConverter
	if lob.variableWidthChar() {
		if conn.dBVersion.Number < 10200 && lob.littleEndianClob() {
			strConv, _ = conn.getStrConv(2002)
		} else {
			strConv, _ = conn.getStrConv(2000)
		}
	} else {
		var err error
		strConv, err = conn.getStrConv(lob.charsetID)
		if err != nil {
			return err
		}
	}
	lobData := strConv.Encode(data)
	// lob.size = int64(len([]rune(data)))
	// lob.sendSize = true
	lob.sourceOffset = 1
	lob.connection.session.ResetBuffer()
	lob.writeOp(0x40)
	lob.connection.session.PutBytes(0xE)
	lob.connection.session.PutClr(lobData)
	err := lob.connection.session.Write()
	if err != nil {
		return err
	}
	return lob.read()
}

// isTemporary: return true if the lob is temporary
func (lob *Lob) isTemporary() bool {
	if len(lob.sourceLocator) > 7 {
		if lob.sourceLocator[7]&1 == 1 || lob.sourceLocator[4]&0x40 == 0x40 {
			return true
		}
	}
	return false
}

func (lob *Lob) freeTemporary() error {
	lob.initialize()
	lob.connection.session.ResetBuffer()
	lob.writeOp(0x111)
	err := lob.connection.session.Write()
	if err != nil {
		return err
	}
	return lob.read()
}

func (lob *Lob) createTemporaryBLOB() error {
	lob.connection.connOption.Tracer.Print("Create Temporary BLob:")
	lob.sourceLocator = make([]byte, 0x28)
	lob.sourceLocator[1] = 0x54
	lob.sourceLen = len(lob.sourceLocator)
	lob.bNullO2U = true
	lob.destOffset = 0x71
	lob.scn = make([]byte, 1)
	lob.destLen = 0xA
	lob.size = 0xA
	lob.sendSize = true
	lob.charsetID = 1
	session := lob.connection.session
	session.ResetBuffer()
	lob.writeOp(0x110)
	err := session.Write()
	if err != nil {
		return err
	}
	return lob.read()
}

func (lob *Lob) createTemporaryClob(charset, charsetForm int) error {
	lob.connection.connOption.Tracer.Print("Create Temporary CLob")
	lob.sourceLocator = make([]byte, 0x28)
	lob.sourceLocator[1] = 0x54
	lob.sourceLen = len(lob.sourceLocator)
	lob.bNullO2U = true
	lob.destOffset = 0x70
	lob.scn = make([]byte, 1)
	lob.size = 0xA
	lob.sendSize = true
	lob.destLen = 0xA
	lob.charsetID = charset
	lob.sourceOffset = int64(charsetForm)
	//if (bNClob) {
	//	lob.charsetID = 0x7D0
	//} else {
	//	lob.charsetID = 0xB2
	//}
	session := lob.connection.session
	session.ResetBuffer()
	lob.writeOp(0x110)
	err := session.Write()
	if err != nil {
		return err
	}
	return lob.read()
}

func (lob *Lob) open(mode, opID int) error {
	lob.connection.connOption.Tracer.Printf("Open Lob: Mode= %d   Operation ID= %d", mode, opID)
	if lob.isTemporary() {
		if lob.sourceLocator[7]&8 == 8 {
			return errors.New("TTC Error")
		}
		if mode == 2 {
			lob.sourceLocator[7] |= 0x10
		}
		return nil
	} else {
		lob.initialize()
		lob.size = int64(mode)
		lob.sendSize = true
		lob.connection.session.ResetBuffer()
		lob.writeOp(opID)
		err := lob.connection.session.Write()
		if err != nil {
			return err
		}
		return lob.read()
	}
}

func (lob *Lob) close(opID int) error {
	lob.connection.connOption.Tracer.Print("Close Lob: ")
	if lob.isTemporary() {
		if lob.sourceLocator[7]&8 == 8 {
			return errors.New("TTC Error")
		}
		lob.sourceLocator[7] &= 0xE7
		return nil
	} else {
		lob.initialize()
		lob.connection.session.ResetBuffer()
		lob.writeOp(opID)
		err := lob.connection.session.Write()
		if err != nil {
			return err
		}
		return lob.read()
	}
}

func (lob *Lob) writeOp(operationID int) {
	session := lob.connection.session
	session.PutBytes(3, 0x60, 0)
	if len(lob.sourceLocator) == 0 {
		session.PutBytes(0)
	} else {
		session.PutBytes(1)
	}
	session.PutUint(lob.sourceLen, 4, true, true)

	if len(lob.destLocator) == 0 {
		session.PutBytes(0)
	} else {
		session.PutBytes(1)
	}
	session.PutUint(lob.destLen, 4, true, true)

	// put offsets
	if session.TTCVersion < 3 {
		session.PutUint(lob.sourceOffset, 4, true, true)
		session.PutUint(lob.destOffset, 4, true, true)
	} else {
		session.PutBytes(0, 0)
	}

	if lob.charsetID != 0 {
		session.PutBytes(1)
	} else {
		session.PutBytes(0)
	}

	if lob.sendSize && session.TTCVersion < 3 {
		session.PutBytes(1)
	} else {
		session.PutBytes(0)
	}

	if lob.bNullO2U {
		session.PutBytes(1)
	} else {
		session.PutBytes(0)
	}

	session.PutInt(operationID, 4, true, true)
	if len(lob.scn) == 0 {
		session.PutBytes(0)
	} else {
		session.PutBytes(1)
	}
	session.PutUint(len(lob.scn), 4, true, true)

	if session.TTCVersion >= 3 {
		session.PutUint(lob.sourceOffset, 8, true, true)
		session.PutInt(lob.destOffset, 8, true, true)
		if lob.sendSize {
			session.PutBytes(1)
		} else {
			session.PutBytes(0)
		}
	}
	if session.TTCVersion >= 4 {
		session.PutBytes(0, 0, 0, 0, 0, 0)
	}

	if len(lob.sourceLocator) > 0 {
		session.PutBytes(lob.sourceLocator...)
	}

	if len(lob.destLocator) > 0 {
		session.PutBytes(lob.destLocator...)
	}

	if lob.charsetID != 0 {
		session.PutUint(lob.charsetID, 2, true, true)
	}
	if session.TTCVersion < 3 && lob.sendSize {
		session.PutUint(lob.size, 4, true, true)
	}
	for x := 0; x < len(lob.scn); x++ {
		session.PutUint(lob.scn[x], 4, true, true)
	}
	if session.TTCVersion >= 3 && lob.sendSize {
		session.PutUint(lob.size, 8, true, true)
	}
}

// read lob response from network session
func (lob *Lob) read() error {
	loop := true
	session := lob.connection.session
	for loop {
		msg, err := session.GetByte()
		if err != nil {
			return err
		}
		switch msg {
		//case 4:
		//	session.Summary, err = network.NewSummary(session)
		//	if err != nil {
		//		return err
		//	}
		//	if session.HasError() {
		//		if session.Summary.RetCode == 1403 {
		//			session.Summary = nil
		//		} else {
		//			return session.GetError()
		//		}
		//	}
		//	loop = false
		case 8:
			// read rpa message
			if len(lob.sourceLocator) != 0 {
				lob.sourceLocator, err = session.GetBytes(len(lob.sourceLocator))
				if err != nil {
					return err
				}
				lob.sourceLen = len(lob.sourceLocator)
			} else {
				lob.sourceLen = 0
			}
			if len(lob.destLocator) != 0 {
				lob.destLocator, err = session.GetBytes(len(lob.destLocator))
				if err != nil {
					return err
				}
				lob.destLen = len(lob.destLocator)
			} else {
				lob.destLen = 0
			}
			if lob.charsetID != 0 {
				lob.charsetID, err = session.GetInt(2, true, true)
				if err != nil {
					return err
				}
			}
			if lob.sendSize {
				// get data size
				if session.TTCVersion < 3 {
					lob.size, err = session.GetInt64(4, true, true)
					if err != nil {
						return err
					}
				} else {
					lob.size, err = session.GetInt64(8, true, true)
					if err != nil {
						return err
					}
				}
			}
			if lob.bNullO2U {
				temp, err := session.GetInt(2, true, true)
				if err != nil {
					return err
				}
				if temp != 0 {
					lob.isNull = true
				}
			}
		//case 9:
		//	if session.HasEOSCapability {
		//		temp, err := session.GetInt(4, true, true)
		//		if err != nil {
		//			return err
		//		}
		//		if session.Summary != nil {
		//			session.Summary.EndOfCallStatus = temp
		//		}
		//	}
		//	loop = false
		case 14:
			// get the data
			err = lob.readData()
			if err != nil {
				return err
			}
		//case 15:
		//	warning, err := network.NewWarningObject(session)
		//	if err != nil {
		//		return err
		//	}
		//	if warning != nil {
		//		fmt.Println(warning)
		//	}
		//case 23:
		//	opCode, err := session.GetByte()
		//	if err != nil {
		//		return err
		//	}
		//	err = lob.connection.getServerNetworkInformation(opCode)
		//	if err != nil {
		//		return err
		//	}
		default:
			err = lob.connection.readResponse(msg)
			if err != nil {
				return err
			}
			if msg == 4 {
				if session.HasError() {
					if session.Summary.RetCode == 1403 {
						session.Summary = nil
					} else {
						return session.GetError()
					}
				}
				loop = false
			}
			if msg == 9 {
				loop = false
			}
			//return errors.New(fmt.Sprintf("TTC error: received code %d during LOB reading", msg))
		}
	}
	if session.IsBreak() {
		err := (&simpleObject{
			connection: lob.connection,
		}).read()
		if err != nil {
			return err
		}
	}
	return nil
}

// read lob data chunks from network session
func (lob *Lob) readData() error {
	session := lob.connection.session
	tempBytes, err := session.GetClr()
	if err != nil {
		return err
	}
	lob.data.Write(tempBytes)
	return nil
	//totalLength := 0 // data readed in the call of this function
	//var chunkSize = 0
	//var err error
	//
	//nb, err := session.GetByte()
	//if err != nil {
	//	return err
	//}
	//chunkSize = int(nb)
	//if chunkSize == 0xFE {
	//	for chunkSize > 0 {
	//		if session.UseBigClrChunks {
	//			chunkSize, err = session.GetInt(4, true, true)
	//		} else {
	//			var nb byte
	//			nb, err = session.GetByte()
	//			chunkSize = int(nb)
	//		}
	//		if err != nil {
	//			return err
	//		}
	//		chunk, err := session.GetBytes(chunkSize)
	//		if err != nil {
	//			return err
	//		}
	//		lob.data.Write(chunk)
	//		totalLength += chunkSize
	//	}
	//} else {
	//	chunk, err := session.GetBytes(chunkSize)
	//	if err != nil {
	//		return err
	//	}
	//	lob.data.Write(chunk)
	//	totalLength += chunkSize
	//}
	////num4 := 0
	////for num4 != 4 {
	////	switch num4 {
	////	case 0:
	////		nb, err := session.GetByte()
	////		if err != nil {
	////			return err
	////		}
	////		chunkSize = int(nb)
	////		if chunkSize == 0xFE {
	////			num4 = 2
	////		} else {
	////			num4 = 1
	////		}
	////	case 1:
	////		chunk, err := session.GetBytes(chunkSize)
	////		if err != nil {
	////			return err
	////		}
	////		lob.data.Write(chunk)
	////		totalLength += chunkSize
	////		num4 = 4
	////	case 2:
	////		if session.UseBigClrChunks {
	////			chunkSize, err = session.GetInt(4, true, true)
	////		} else {
	////			var nb byte
	////			nb, err = session.GetByte()
	////			chunkSize = int(nb)
	////		}
	////		if err != nil {
	////			return err
	////		}
	////		if chunkSize <= 0 {
	////			num4 = 4
	////		} else {
	////			num4 = 3
	////		}
	////	case 3:
	////		chunk, err := session.GetBytes(chunkSize)
	////		if err != nil {
	////			return err
	////		}
	////		lob.data.Write(chunk)
	////		totalLength += chunkSize
	////		//num3 += chunkSize
	////		num4 = 2
	////	}
	////}
	//return nil
}

func (lob *Lob) GetLobId(locator []byte) []byte {
	//BitConverter.ToString(lobLocator, 10, 10);
	return locator[10 : 10+10]
}

func (lob *Lob) append(dest []byte) error {
	lob.initialize()
	lob.destLocator = dest
	lob.destLen = len(dest)
	lob.connection.session.ResetBuffer()
	lob.writeOp(0x80)
	err := lob.connection.session.Write()
	if err != nil {
		return err
	}
	return lob.read()
}

func (lob *Lob) copy(srcLocator, dstLocator []byte, srcOffset, dstOffset, length int64) error {
	lob.initialize()
	lob.sourceLocator = srcLocator
	lob.sourceLen = len(srcLocator)
	lob.destLocator = dstLocator
	lob.destLen = len(dstLocator)
	lob.sourceOffset = srcOffset
	lob.destOffset = dstOffset
	lob.size = length
	lob.sendSize = true
	lob.connection.session.ResetBuffer()
	lob.writeOp(4)
	err := lob.connection.session.Write()
	if err != nil {
		return err
	}
	return lob.read()
}

func (val *Clob) Scan(value interface{}) error {
	val.Valid = true
	if value == nil {
		val.Valid = false
		val.String = ""
		return nil
	}
	switch temp := value.(type) {
	case Clob:
		*val = temp
	case *Clob:
		*val = *temp
	case NClob:
		*val = Clob(temp)
	case *NClob:
		*val = Clob(*temp)
	case string:
		val.String = temp
	case types.Nil:
		val.String = ""
		val.Valid = false
	default:
		return errors.New("go-ora: Clob column type require Clob or string values")
	}
	return nil
}

func (val *Blob) Scan(value interface{}) error {
	val.Valid = true
	if value == nil {
		val.Valid = false
		val.Data = nil
		return nil
	}
	switch temp := value.(type) {
	case Blob:
		*val = temp
	case *Blob:
		*val = *temp
	case []byte:
		val.Data = temp
	case types.Nil:
		val.Data = nil
		val.Valid = false
	default:
		return errors.New("go-ora: Blob column type require Blob or []byte values")
	}
	return nil
}

func (val *NClob) Scan(value interface{}) error {
	val.Valid = true
	if value == nil {
		val.Valid = false
		val.String = ""
		return nil
	}
	switch temp := value.(type) {
	case Clob:
		*val = NClob(temp)
	case *Clob:
		*val = NClob(*temp)
	case NClob:
		*val = temp
	case *NClob:
		*val = *temp
	case string:
		val.String = temp
	case types.Nil:
		val.String = ""
		val.Valid = false
	default:
		return errors.New("go-ora: Clob column type require Clob or string values")
	}
	return nil
}

func (val Blob) getLocator() []byte {
	return val.locator
}
func (val Clob) getLocator() []byte {
	return val.locator
}
func (val NClob) getLocator() []byte {
	return val.locator
}

//func (val Clob) Value() (driver.Value, error) {
//	if val.Valid {
//		return val.String, nil
//	} else {
//		return nil, nil
//	}
//}

//
//func (val *NClob) Value() (driver.Value, error) {
//	if val.Valid {
//		return val.String, nil
//	} else {
//		return nil, nil
//	}
//}
//
//func (val *Blob) Value() (driver.Value, error) {
//	if val.Valid {
//		return val.Data, nil
//	} else {
//		return nil, nil
//	}
//}
