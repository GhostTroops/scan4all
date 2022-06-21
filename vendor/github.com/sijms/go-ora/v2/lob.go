package go_ora

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/sijms/go-ora/v2/network"
)

type Clob struct {
	locator []byte
	String  string
	Valid   bool
}

type NClob Clob

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
	lob.charsetID = 0
	lob.sourceOffset = 0
	lob.destOffset = 0
	lob.scn = nil
}

// variableWidthChar if lob has variable width char or not
func (lob *Lob) variableWidthChar() bool {
	if len(lob.sourceLocator) > 6 && lob.sourceLocator[6]&128 == 128 {
		return true
	}
	return false
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
func (lob *Lob) putString(data string, charset int) error {
	lob.connection.connOption.Tracer.Printf("Put Lob String: %d character", int64(len([]rune(data))))
	lob.initialize()
	lob.charsetID = charset
	tempCharset := lob.connection.strConv.GetLangID()
	if lob.variableWidthChar() {
		if lob.connection.dBVersion.Number < 10200 && lob.littleEndianClob() {
			lob.connection.strConv.SetLangID(2002)
		} else {
			lob.connection.strConv.SetLangID(2000)
		}
	} else {
		lob.connection.strConv.SetLangID(lob.charsetID)
	}
	lobData := lob.connection.strConv.Encode(data)
	lob.connection.strConv.SetLangID(tempCharset)
	lob.size = int64(len([]rune(data)))
	lob.sendSize = true
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

//isTemporary: return true if the lob is temporary
func (lob *Lob) isTemporary() bool {
	if len(lob.sourceLocator) > 7 {
		if lob.sourceLocator[7]&1 == 1 || lob.sourceLocator[4]&0x40 == 0x40 {
			return true
		}
	}
	return false
}

//freeAllTemporary: free temporary lobs defined by all_locators
func (lob *Lob) freeAllTemporary(all_locators [][]byte) error {
	if len(all_locators) == 0 {
		return nil
	}
	lob.connection.connOption.Tracer.Printf("Free %d Temporary Lobs", len(all_locators))
	session := lob.connection.session
	freeTemp := func(locators [][]byte) {
		totalLen := 0
		for _, locator := range locators {
			totalLen += len(locator)
		}
		session.PutBytes(0x11, 0x60, 0, 1)
		session.PutUint(totalLen, 4, true, true)
		session.PutBytes(0, 0, 0, 0, 0, 0, 0)
		session.PutUint(0x80111, 4, true, true)
		session.PutBytes(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
		for _, locator := range locators {
			session.PutBytes(locator...)
		}
	}
	start := 0
	end := 0
	session.ResetBuffer()
	for start < len(all_locators) {
		end = start + 25000
		if end > len(all_locators) {
			end = len(all_locators)
		}
		freeTemp(all_locators[start:end])
		start += end
	}
	session.PutBytes(0x3, 0x93, 0x0)
	err := session.Write()
	if err != nil {
		return err
	}
	return (&simpleObject{
		connection: lob.connection,
	}).read()
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
		case 4:
			session.Summary, err = network.NewSummary(session)
			if err != nil {
				return err
			}
			if session.HasError() {
				if session.Summary.RetCode == 1403 {
					session.Summary = nil
				} else {
					return session.GetError()
				}
			}
			loop = false

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
		case 9:
			if session.HasEOSCapability {
				temp, err := session.GetInt(4, true, true)
				if err != nil {
					return err
				}
				if session.Summary != nil {
					session.Summary.EndOfCallStatus = temp
				}
			}
			loop = false
		case 14:
			// get the data
			err = lob.readData()
			if err != nil {
				return err
			}
		case 15:
			warning, err := network.NewWarningObject(session)
			if err != nil {
				return err
			}
			if warning != nil {
				fmt.Println(warning)
			}
		case 23:
			opCode, err := session.GetByte()
			if err != nil {
				return err
			}
			err = lob.connection.getServerNetworkInformation(opCode)
			if err != nil {
				return err
			}
		default:
			return errors.New(fmt.Sprintf("TTC error: received code %d during LOB reading", msg))
		}
	}
	return nil
}

// read lob data chunks from network session
func (lob *Lob) readData() error {
	session := lob.connection.session
	num1 := 0 // data readed in the call of this function
	var chunkSize = 0
	var err error
	//num3 := offset // the data readed from the start of read operation
	num4 := 0
	for num4 != 4 {
		switch num4 {
		case 0:
			nb, err := session.GetByte()
			if err != nil {
				return err
			}
			chunkSize = int(nb)
			if chunkSize == 0xFE {
				num4 = 2
			} else {
				num4 = 1
			}
		case 1:
			chunk, err := session.GetBytes(chunkSize)
			if err != nil {
				return err
			}
			lob.data.Write(chunk)
			num1 += chunkSize
			num4 = 4
		case 2:
			if session.UseBigClrChunks {
				chunkSize, err = session.GetInt(4, true, true)
			} else {
				var nb byte
				nb, err = session.GetByte()
				chunkSize = int(nb)
			}
			if err != nil {
				return err
			}
			if chunkSize <= 0 {
				num4 = 4
			} else {
				num4 = 3
			}
		case 3:
			chunk, err := session.GetBytes(chunkSize)
			if err != nil {
				return err
			}
			lob.data.Write(chunk)
			num1 += chunkSize
			//num3 += chunkSize
			num4 = 2
		}
	}
	return nil
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
