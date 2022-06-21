package go_ora

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/sijms/go-ora/v2/network"
	"reflect"
	"regexp"
	"strings"
)

type StmtType int

const (
	SELECT StmtType = 1
	DML    StmtType = 2
	PLSQL  StmtType = 3
	OTHERS StmtType = 4
)

type StmtInterface interface {
	hasMoreRows() bool
	noOfRowsToFetch() int
	fetch(dataSet *DataSet) error
	hasBLOB() bool
	hasLONG() bool
	read(dataSet *DataSet) error
	Close() error
	CanAutoClose() bool
}
type defaultStmt struct {
	connection         *Connection
	text               string
	disableCompression bool
	_hasLONG           bool
	_hasBLOB           bool
	_hasMoreRows       bool
	_hasReturnClause   bool
	_noOfRowsToFetch   int
	stmtType           StmtType
	cursorID           int
	queryID            uint64
	Pars               []ParameterInfo
	columns            []ParameterInfo
	scnForSnapshot     []int
	arrayBindCount     int
	containOutputPars  bool
	autoClose          bool
}

func (stmt defaultStmt) CanAutoClose() bool {
	return stmt.autoClose
}
func (stmt *defaultStmt) hasMoreRows() bool {
	return stmt._hasMoreRows
}

func (stmt *defaultStmt) noOfRowsToFetch() int {
	return stmt._noOfRowsToFetch
}

func (stmt *defaultStmt) hasLONG() bool {
	return stmt._hasLONG
}

func (stmt *defaultStmt) hasBLOB() bool {
	return stmt._hasBLOB
}

// basicWrite this is the default write procedure for the all type of stmt
// through it the stmt data will send to network stream
func (stmt *defaultStmt) basicWrite(exeOp int, parse, define bool) error {
	session := stmt.connection.session
	session.PutBytes(3, 0x5E, 0)
	session.PutUint(exeOp, 4, true, true)
	session.PutUint(stmt.cursorID, 2, true, true)
	if stmt.cursorID == 0 {
		session.PutBytes(1)

	} else {
		session.PutBytes(0)
	}
	if parse {
		session.PutUint(len(stmt.connection.strConv.Encode(stmt.text)), 4, true, true)
		session.PutBytes(1)
	} else {
		session.PutBytes(0, 1)
	}
	session.PutUint(13, 2, true, true)
	session.PutBytes(0, 0)
	if exeOp&0x40 == 0 && exeOp&0x20 != 0 && exeOp&0x1 != 0 && stmt.stmtType == SELECT {
		session.PutBytes(0)
		session.PutUint(stmt._noOfRowsToFetch, 4, true, true)
	} else {
		session.PutUint(0, 4, true, true)
		session.PutUint(0, 4, true, true)
	}
	//switch (longFetchSize)
	//{
	//case -1:
	//	this.m_marshallingEngine.MarshalUB4((long) int.MaxValue);
	//	break;
	//case 0:
	//	this.m_marshallingEngine.MarshalUB4(1L);
	//	break;
	//default:
	//	this.m_marshallingEngine.MarshalUB4((long) longFetchSize);
	//	break;
	//}
	// we use here int.MaxValue
	session.PutUint(0x7FFFFFFF, 4, true, true)
	//session.PutInt(1, 4, true, true)
	if len(stmt.Pars) > 0 {
		session.PutBytes(1)
		session.PutUint(len(stmt.Pars), 2, true, true)
	} else {
		session.PutBytes(0, 0)
	}
	session.PutBytes(0, 0, 0, 0, 0)
	if define {
		session.PutBytes(1)
		session.PutUint(len(stmt.columns), 2, true, true)
	} else {
		session.PutBytes(0, 0)
	}
	if session.TTCVersion >= 4 {
		session.PutBytes(0, 0, 1)
	}
	if session.TTCVersion >= 5 {
		session.PutBytes(0, 0, 0, 0, 0)
	}
	if session.TTCVersion >= 7 {
		if stmt.stmtType == DML && stmt.arrayBindCount > 0 {
			session.PutBytes(1)
			session.PutInt(stmt.arrayBindCount, 4, true, true)
			session.PutBytes(1)
		} else {
			session.PutBytes(0, 0, 0)
		}
	}
	if session.TTCVersion >= 8 {
		session.PutBytes(0, 0, 0, 0, 0)
	}
	if session.TTCVersion >= 9 {
		session.PutBytes(0, 0)
	}
	if parse {
		session.PutClr(stmt.connection.strConv.Encode(stmt.text))
	}
	if define {
		session.PutBytes(0)
		for x := 0; x < len(stmt.columns); x++ {
			stmt.columns[x].Flag = 3
			stmt.columns[x].CharsetForm = 1
			//stmt.columns[x].MaxLen = 0x7fffffff
			err := stmt.columns[x].write(session)
			if err != nil {
				return err
			}
			session.PutBytes(0)
		}
	} else {
		al8i4 := make([]int, 13)
		if exeOp&1 <= 0 {
			al8i4[0] = 0
		} else {
			al8i4[0] = 1
		}
		switch stmt.stmtType {
		case DML:
			fallthrough
		case PLSQL:
			if stmt.arrayBindCount > 0 {
				al8i4[1] = stmt.arrayBindCount
				if stmt.stmtType == DML {
					al8i4[9] = 0x4000
				}
			} else {
				al8i4[1] = 1
			}
		case OTHERS:
			al8i4[1] = 1
		default:
			//this.m_al8i4[1] = !fetch ? 0L : noOfRowsToFetch;
			al8i4[1] = stmt._noOfRowsToFetch
		}
		if len(stmt.scnForSnapshot) == 2 {
			al8i4[5] = stmt.scnForSnapshot[0]
			al8i4[6] = stmt.scnForSnapshot[1]
		} else {
			al8i4[5] = 0
			al8i4[6] = 0
		}
		if stmt.stmtType == SELECT {
			al8i4[7] = 1
		} else {
			al8i4[7] = 0
		}
		if exeOp&32 != 0 {
			al8i4[9] |= 0x8000
		} else {
			al8i4[9] &= -0x8000
		}
		for x := 0; x < len(al8i4); x++ {
			session.PutUint(al8i4[x], 4, true, true)
		}
	}
	for _, par := range stmt.Pars {
		_ = par.write(session)
	}
	return nil
}

type Stmt struct {
	defaultStmt
	//reExec           bool
	reSendParDef bool
	parse        bool // means parse the command in the server this occurs if the stmt is not cached
	execute      bool
	define       bool

	//noOfDefCols        int
}

type QueryResult struct {
	lastInsertedID int64
	rowsAffected   int64
}

func (rs *QueryResult) LastInsertId() (int64, error) {
	return rs.lastInsertedID, nil
}

func (rs *QueryResult) RowsAffected() (int64, error) {
	return rs.rowsAffected, nil
}

// NewStmt create new stmt and set its connection properties
func NewStmt(text string, conn *Connection) *Stmt {
	ret := &Stmt{
		reSendParDef: false,
		parse:        true,
		execute:      true,
		define:       false,
	}
	ret.connection = conn
	ret.text = text
	ret._hasBLOB = false
	ret._hasLONG = false
	ret.disableCompression = true
	ret.arrayBindCount = 0
	ret.scnForSnapshot = make([]int, 2)
	// get stmt type
	uCmdText := strings.TrimSpace(strings.ToUpper(text))
	for {
		if strings.HasPrefix(uCmdText, "--") {
			i := strings.Index(uCmdText, "\n")
			if i <= 0 {
				break
			}
			uCmdText = uCmdText[i+1:]
		} else {
			break
		}
	}
	if strings.HasPrefix(uCmdText, "(") {
		uCmdText = uCmdText[1:]
	}
	if strings.HasPrefix(uCmdText, "SELECT") || strings.HasPrefix(uCmdText, "WITH") {
		ret.stmtType = SELECT
	} else if strings.HasPrefix(uCmdText, "UPDATE") ||
		strings.HasPrefix(uCmdText, "INSERT") ||
		strings.HasPrefix(uCmdText, "DELETE") {
		ret.stmtType = DML
	} else if strings.HasPrefix(uCmdText, "DECLARE") || strings.HasPrefix(uCmdText, "BEGIN") {
		ret.stmtType = PLSQL
	} else {
		ret.stmtType = OTHERS
	}

	// returning clause
	var err error
	if ret.stmtType != PLSQL {
		ret._hasReturnClause, err = regexp.MatchString(`\bRETURNING\b\s+\w+\s+\bINTO\b`, uCmdText)
		if err != nil {
			ret._hasReturnClause = false
		}
	}
	return ret
}

func (stmt *Stmt) writePars(session *network.Session) error {
	if len(stmt.Pars) > 0 {
		session.PutBytes(7)
		for _, par := range stmt.Pars {
			if !stmt.parse && par.Direction == Output && stmt.stmtType != PLSQL {
				continue
			}
			if par.DataType != RAW {
				if par.DataType == REFCURSOR {
					session.PutBytes(1, 0)
				} else if par.Direction == Input &&
					(par.DataType == OCIClobLocator || par.DataType == OCIBlobLocator || par.DataType == OCIFileLocator) {
					session.PutUint(len(par.BValue), 2, true, true)
					session.PutClr(par.BValue)
				} else {
					if par.cusType != nil {
						size := len(par.BValue) + 7
						session.PutBytes(0, 0, 0, 0)
						session.PutUint(size, 4, true, true)
						session.PutBytes(1, 1)
						tempBuffer := bytes.Buffer{}
						tempBuffer.Write([]byte{0x84, 0x1, 0xfe})
						session.WriteUint(&tempBuffer, size, 4, true, false)
						tempBuffer.Write(par.BValue)
						session.PutClr(tempBuffer.Bytes())
					} else {
						if par.MaxNoOfArrayElements > 0 {
							if par.BValue == nil {
								session.PutBytes(0)
							} else {
								session.PutBytes(par.BValue...)
							}
						} else {
							session.PutClr(par.BValue)
						}
					}
				}
			}
		}
		for _, par := range stmt.Pars {
			if par.DataType == RAW {
				session.PutClr(par.BValue)
			}
		}
	}
	return nil
}

// write stmt data to network stream
func (stmt *Stmt) write(session *network.Session) error {
	if !stmt.parse && !stmt.reSendParDef {
		exeOf := 0
		execFlag := 0
		count := 1
		if stmt.arrayBindCount > 0 {
			count = stmt.arrayBindCount
		}
		if stmt.stmtType == SELECT {
			session.PutBytes(3, 0x4E, 0)
			count = stmt._noOfRowsToFetch
			exeOf = 0x20
			if stmt._hasReturnClause || stmt.stmtType == PLSQL || stmt.disableCompression {
				exeOf |= 0x40000
			}

		} else {
			session.PutBytes(3, 4, 0)
		}
		if stmt.connection.autoCommit {
			execFlag = 1
		}
		session.PutUint(stmt.cursorID, 2, true, true)
		session.PutUint(count, 2, true, true)
		session.PutUint(exeOf, 2, true, true)
		session.PutUint(execFlag, 2, true, true)
		err := stmt.writePars(session)
		if err != nil {
			return err
		}
	} else {
		//stmt.reExec = true
		err := stmt.basicWrite(stmt.getExeOption(), stmt.parse, stmt.define)
		if err != nil {
			return err
		}
		err = stmt.writePars(session)
		if err != nil {
			return err
		}
		stmt.parse = false
		stmt.define = false
		stmt.reSendParDef = false
	}
	return session.Write()
}

// getExeOption return an integer that act like a flag carry bit value set according
// to stmt properties
func (stmt *Stmt) getExeOption() int {
	op := 0
	if stmt.stmtType == PLSQL || stmt._hasReturnClause {
		op |= 0x40000
	}
	if stmt.arrayBindCount > 1 {
		op |= 0x80000
	}
	if stmt.connection.autoCommit && (stmt.stmtType == DML || stmt.stmtType == PLSQL) {
		op |= 0x100
	}
	if stmt.parse {
		op |= 1
	}
	if stmt.execute {
		op |= 0x20
	}
	if !stmt.parse && !stmt.execute {
		op |= 0x40
	}
	if len(stmt.Pars) > 0 {
		op |= 0x8
		if stmt.stmtType == PLSQL || stmt._hasReturnClause {
			op |= 0x400
		}
	}
	if stmt.stmtType != PLSQL && !stmt._hasReturnClause {
		op |= 0x8000
	}
	if stmt.define {
		op |= 0x10
	}
	return op

	/* HasReturnClause
	if  stmt.PLSQL or cmdText == "" return false
	Regex.IsMatch(cmdText, "\\bRETURNING\\b"
	*/
}

// fetch get more rows from network stream
func (stmt *defaultStmt) fetch(dataSet *DataSet) error {
	//stmt._noOfRowsToFetch = stmt.connection.connOption.PrefetchRows
	// note if _noOfRowsToFetch is default i will try to calculate the best value for
	// according to the query
	if stmt._noOfRowsToFetch == 25 {
		//m_maxRowSize = m_maxRowSize + m_numOfLOBColumns * Math.Max(86, 86 + (int) lobSize) + m_numOfLONGColumns * Math.Max(2, longSize) + m_numOfBFileColumns * 86;
		maxRowSize := 0
		for _, col := range dataSet.Cols {
			if col.DataType == OCIClobLocator || col.DataType == OCIBlobLocator {
				maxRowSize += 86
			} else if col.DataType == LONG || col.DataType == LongRaw {
				maxRowSize += 2
			} else if col.DataType == OCIFileLocator {
				maxRowSize += 86
			} else {
				maxRowSize += col.MaxLen
			}
		}
		stmt._noOfRowsToFetch = (0x20000 / maxRowSize) + 1
		stmt.connection.connOption.Tracer.Printf("Fetch Size Calculated: %d", stmt._noOfRowsToFetch)
	}
	stmt.connection.session.ResetBuffer()
	stmt.connection.session.PutBytes(3, 5, 0)
	stmt.connection.session.PutInt(stmt.cursorID, 2, true, true)
	stmt.connection.session.PutInt(stmt._noOfRowsToFetch, 2, true, true)
	err := stmt.connection.session.Write()
	if err != nil {
		return err
	}
	return stmt.read(dataSet)
}

// read this is common read for stmt it read many information related to
// columns, dataset information, output parameter information, rows values
// and at the end summary object about this operation
func (stmt *defaultStmt) read(dataSet *DataSet) error {
	loop := true
	after7 := false
	dataSet.parent = stmt
	session := stmt.connection.session
	for loop {
		msg, err := session.GetByte()
		if err != nil {
			return err
		}
		switch msg {
		case 4:
			stmt.connection.session.Summary, err = network.NewSummary(session)
			if err != nil {
				return err
			}
			stmt.connection.connOption.Tracer.Printf("Summary: RetCode:%d, Error Message:%q", stmt.connection.session.Summary.RetCode, string(stmt.connection.session.Summary.ErrorMessage))

			stmt.cursorID = stmt.connection.session.Summary.CursorID
			stmt.disableCompression = stmt.connection.session.Summary.Flags&0x20 != 0
			if stmt.connection.session.HasError() {
				if stmt.connection.session.Summary.RetCode == 1403 {
					stmt._hasMoreRows = false
					stmt.connection.session.Summary = nil
				} else {
					return stmt.connection.session.GetError()
				}

			}
			loop = false
		case 6:
			//_, err = session.GetByte()
			err = dataSet.load(session)
			if err != nil {
				return err
			}
			if !after7 {
				if stmt.stmtType == SELECT {
					//b, _ := session.GetBytes(0x10)
					//fmt.Printf("%#v\n", b)
					//return errors.New("interrupt")
				}
			}
		case 7:
			after7 = true
			if stmt._hasReturnClause && stmt.containOutputPars {
				for x := 0; x < len(stmt.Pars); x++ {
					if stmt.Pars[x].Direction == Output {
						num, err := session.GetInt(4, true, true)
						if err != nil {
							return err
						}
						if num > 1 {
							return errors.New("more than one row affected with return clause")
						}
						if num == 0 {
							stmt.Pars[x].BValue = nil
							stmt.Pars[x].Value = nil
						} else {

							err = stmt.calculateParameterValue(&stmt.Pars[x])
							if err != nil {
								return err
							}
							_, err = session.GetInt(2, true, true)
							if err != nil {
								return err
							}
						}
					}
				}
			} else {
				if stmt.containOutputPars {
					for x := 0; x < len(stmt.Pars); x++ {
						if stmt.Pars[x].DataType == REFCURSOR {
							typ := reflect.TypeOf(stmt.Pars[x].Value)
							if typ.Kind() == reflect.Ptr {
								if cursor, ok := stmt.Pars[x].Value.(*RefCursor); ok {
									cursor.connection = stmt.connection
									cursor.parent = stmt
									err = cursor.load()
									if err != nil {
										return err
									}
								} else {
									return errors.New("RefCursor parameter should contain pointer to  RefCursor struct")
								}
							} else {
								return errors.New("RefCursor parameter should contain pointer to  RefCursor struct")
							}
						} else {
							if stmt.Pars[x].Direction != Input {
								err = stmt.calculateParameterValue(&stmt.Pars[x])
								if err != nil {
									return err
								}
								_, err = session.GetInt(2, true, true)
								if err != nil {
									return err
								}
							} else {
								//_, err = session.GetClr()
							}

						}
					}
				} else {
					// see if it is re-execute
					if len(dataSet.Cols) == 0 && len(stmt.columns) > 0 {
						dataSet.Cols = make([]ParameterInfo, len(stmt.columns))
						copy(dataSet.Cols, stmt.columns)
					}
					for x := 0; x < len(dataSet.Cols); x++ {
						if dataSet.Cols[x].getDataFromServer {
							err = stmt.calculateColumnValue(&dataSet.Cols[x])
							if err != nil {
								return err
							}
							if dataSet.Cols[x].DataType == LONG || dataSet.Cols[x].DataType == LongRaw {
								_, err = session.GetInt(4, true, true)
								if err != nil {
									return err
								}
								_, err = session.GetInt(4, true, true)
								if err != nil {
									return err
								}
							}
						}
					}
					newRow := make(Row, dataSet.columnCount)
					for x := 0; x < len(dataSet.Cols); x++ {
						newRow[x] = dataSet.Cols[x].Value
					}
					//copy(newRow, dataSet.currentRow)
					dataSet.rows = append(dataSet.rows, newRow)
				}
			}
		case 8:
			size, err := session.GetInt(2, true, true)
			if err != nil {
				return err
			}
			for x := 0; x < 2; x++ {
				stmt.scnForSnapshot[x], err = session.GetInt(4, true, true)
				if err != nil {
					return err
				}
			}
			for x := 2; x < size; x++ {
				_, err = session.GetInt(4, true, true)
				if err != nil {
					return err
				}
			}
			_, err = session.GetInt(2, true, true)
			if err != nil {
				return err
			}
			//if num > 0 {
			//	_, err = session.GetBytes(num)
			//	if err != nil {
			//		return err
			//	}
			//}
			//fmt.Println(num)
			//if (num > 0)
			//	this.m_marshallingEngine.UnmarshalNBytes_ScanOnly(num);
			// get session timezone
			size, err = session.GetInt(2, true, true)
			for x := 0; x < size; x++ {
				_, val, num, err := session.GetKeyVal()
				if err != nil {
					return err
				}
				//fmt.Println(key, val, num)
				if num == 163 {
					session.TimeZone = val
					//fmt.Println("session time zone", session.TimeZone)
				}
			}
			if session.TTCVersion >= 4 {
				// get queryID
				size, err = session.GetInt(4, true, true)
				if err != nil {
					return err
				}
				if size > 0 {
					bty, err := session.GetBytes(size)
					if err != nil {
						return err
					}
					if len(bty) >= 8 {
						stmt.queryID = binary.LittleEndian.Uint64(bty[size-8:])
						fmt.Println("query ID: ", stmt.queryID)
					}
				}
			}
			if session.TTCVersion >= 7 && stmt.stmtType == DML && stmt.arrayBindCount > 0 {
				length, err := session.GetInt(4, true, true)
				if err != nil {
					return err
				}
				//for (int index = 0; index < length3; ++index)
				//	rowsAffectedByArrayBind[index] = this.m_marshallingEngine.UnmarshalSB8();
				for i := 0; i < length; i++ {
					_, err = session.GetInt(8, true, true)
					if err != nil {
						return err
					}
				}
			}
		case 11:
			err = dataSet.load(session)
			if err != nil {
				return err
			}
			//dataSet.BindDirections = make([]byte, dataSet.columnCount)
			for x := 0; x < dataSet.columnCount; x++ {
				direction, err := session.GetByte()
				switch direction {
				case 32:
					stmt.Pars[x].Direction = Input
				case 16:
					stmt.Pars[x].Direction = Output
					stmt.containOutputPars = true
				case 48:
					stmt.Pars[x].Direction = InOut
					stmt.containOutputPars = true
				}
				if err != nil {
					return err
				}
			}
		case 16:
			size, err := session.GetByte()
			if err != nil {
				return err
			}
			_, err = session.GetBytes(int(size))
			if err != nil {
				return err
			}
			dataSet.maxRowSize, err = session.GetInt(4, true, true)
			if err != nil {
				return err
			}
			dataSet.columnCount, err = session.GetInt(4, true, true)
			if err != nil {
				return err
			}
			if dataSet.columnCount > 0 {
				_, err = session.GetByte() // session.GetInt(1, false, false)
			}
			dataSet.Cols = make([]ParameterInfo, dataSet.columnCount)
			for x := 0; x < dataSet.columnCount; x++ {
				err = dataSet.Cols[x].load(stmt.connection)
				if err != nil {
					return err
				}
				if dataSet.Cols[x].DataType == LONG || dataSet.Cols[x].DataType == LongRaw {
					stmt._hasLONG = true
				}
				if dataSet.Cols[x].DataType == OCIClobLocator || dataSet.Cols[x].DataType == OCIBlobLocator {
					stmt._hasBLOB = true
				}
			}
			stmt.columns = make([]ParameterInfo, dataSet.columnCount)
			copy(stmt.columns, dataSet.Cols)
			_, err = session.GetDlc()
			if session.TTCVersion >= 3 {
				_, err = session.GetInt(4, true, true)
				_, err = session.GetInt(4, true, true)
			}
			if session.TTCVersion >= 4 {
				_, err = session.GetInt(4, true, true)
				_, err = session.GetInt(4, true, true)
			}
			if session.TTCVersion >= 5 {
				_, err = session.GetDlc()
			}
		case 21:
			_, err := session.GetInt(2, true, true) // noOfColumnSent
			if err != nil {
				return err
			}
			bitVectorLen := dataSet.columnCount / 8
			if dataSet.columnCount%8 > 0 {
				bitVectorLen++
			}
			bitVector := make([]byte, bitVectorLen)
			for x := 0; x < bitVectorLen; x++ {
				bitVector[x], err = session.GetByte()
				if err != nil {
					return err
				}
			}
			dataSet.setBitVector(bitVector)
		case 23:
			opCode, err := session.GetByte()
			if err != nil {
				return err
			}
			err = stmt.connection.getServerNetworkInformation(opCode)
			if err != nil {
				return err
			}
		default:
			return errors.New(fmt.Sprintf("TTC error: received code %d during stmt reading", msg))
		}
	}
	if stmt.connection.connOption.Tracer.IsOn() {
		dataSet.Trace(stmt.connection.connOption.Tracer)
	}
	return stmt.readLobs(dataSet)
	//return nil
}

func (stmt *defaultStmt) freeTemporaryLobs() error {
	var locators [][]byte
	for _, par := range stmt.Pars {
		if par.Direction == Input {
			switch value := par.Value.(type) {
			case Clob:
				if value.locator != nil {
					locators = append(locators, value.locator)
				}
			case *Clob:
				if value.locator != nil {
					locators = append(locators, value.locator)
				}
			case Blob:
				if value.locator != nil {
					locators = append(locators, value.locator)
				}
			case *Blob:
				if value.locator != nil {
					locators = append(locators, value.locator)
				}
			}
		}
	}
	return (&Lob{connection: stmt.connection}).freeAllTemporary(locators)
}
func (stmt *defaultStmt) readLob(col ParameterInfo, locator []byte) (driver.Value, error) {
	if locator == nil {
		return nil, nil
	}
	lob := &Lob{
		connection:    stmt.connection,
		sourceLocator: locator,
		sourceLen:     len(locator),
	}
	dataSize, err := lob.getSize()
	if err != nil {
		return nil, err
	}
	lobData, err := lob.getData()
	if err != nil {
		return nil, err
	}
	if col.DataType == OCIBlobLocator {
		//if !lob.isValid() {
		//
		//}
		if dataSize != int64(len(lobData)) {
			return nil, errors.New("error reading lob data: data size mismatching")
		}
		return lobData, nil
	} else {
		tempCharset := stmt.connection.strConv.GetLangID()
		if lob.variableWidthChar() {
			if stmt.connection.dBVersion.Number < 10200 && lob.littleEndianClob() {
				stmt.connection.strConv.SetLangID(2002)
			} else {
				stmt.connection.strConv.SetLangID(2000)
			}
		} else {
			stmt.connection.strConv.SetLangID(col.CharsetID)
		}
		resultClobString := stmt.connection.strConv.Decode(lobData)
		stmt.connection.strConv.SetLangID(tempCharset)
		//if dataSize != int64(len([]rune(resultClobString))) {
		//	return nil, errors.New("error reading clob data")
		//}
		return resultClobString, nil
	}
}
func (stmt *defaultStmt) readLobs(dataSet *DataSet) error {
	if stmt._hasBLOB {
		if stmt.containOutputPars {
			for parIndex, par := range stmt.Pars {
				if par.DataType == OCIBlobLocator || par.DataType == OCIClobLocator {
					switch val := par.Value.(type) {
					case *Clob:
						if val.locator == nil {
							val.Valid = false
							val.String = ""
						} else {
							tempVal, err := stmt.readLob(par, val.locator)
							if err != nil {
								return err
							}
							if stringVal, ok := tempVal.(string); ok {
								val.String = stringVal
							} else {
								return &network.OracleError{ErrCode: 6502, ErrMsg: "numberic or value error"}
							}
						}
					case Clob:
						if val.locator == nil {
							val.Valid = false
							val.String = ""
						} else {
							tempVal, err := stmt.readLob(par, val.locator)
							if err != nil {
								return err
							}
							if stringVal, ok := tempVal.(string); ok {
								val.String = stringVal
							} else {
								return &network.OracleError{ErrCode: 6502, ErrMsg: "numberic or value error"}
							}
						}
						stmt.Pars[parIndex].Value = val
					case *Blob:
						if val.locator == nil {
							val.Valid = false
							val.Data = nil
						} else {
							tempVal, err := stmt.readLob(par, val.locator)
							if err != nil {
								return err
							}
							if byteVal, ok := tempVal.([]byte); ok {
								val.Data = byteVal
							} else {
								return &network.OracleError{ErrCode: 6502, ErrMsg: "numberic or value error"}
							}
						}
					case Blob:
						if val.locator == nil {
							val.Valid = false
							val.Data = nil
						} else {
							tempVal, err := stmt.readLob(par, val.locator)
							if err != nil {
								return err
							}
							if byteVal, ok := tempVal.([]byte); ok {
								val.Data = byteVal
							} else {
								return &network.OracleError{ErrCode: 6502, ErrMsg: "numberic or value error"}
							}
						}
						stmt.Pars[parIndex].Value = val
					}
				}
			}
		} else {
			for colIndex, col := range dataSet.Cols {
				if col.DataType == OCIBlobLocator || col.DataType == OCIClobLocator {
					for _, row := range dataSet.rows {
						//if row[colIndex] == nil {
						//	continue
						//}
						switch val := row[colIndex].(type) {
						case *Clob:
							if val.locator == nil {
								row[colIndex] = nil
							} else {
								tempVal, err := stmt.readLob(col, val.locator)
								if err != nil {
									return err
								}
								if stringVal, ok := tempVal.(string); ok {
									row[colIndex] = stringVal
								} else {
									return &network.OracleError{ErrCode: 6502, ErrMsg: "numeric or value error"}
								}
							}
						case Clob:
							if val.locator == nil {
								row[colIndex] = nil
							} else {
								tempVal, err := stmt.readLob(col, val.locator)
								if err != nil {
									return err
								}
								if stringVal, ok := tempVal.(string); ok {
									row[colIndex] = stringVal
								} else {
									return &network.OracleError{ErrCode: 6502, ErrMsg: "numeric or value error"}
								}
							}
						case *Blob:
							if val.locator == nil {
								row[colIndex] = nil
							} else {
								tempVal, err := stmt.readLob(col, val.locator)
								if err != nil {
									return err
								}
								if byteVal, ok := tempVal.([]byte); ok {
									row[colIndex] = byteVal
								} else {
									return &network.OracleError{ErrCode: 6502, ErrMsg: "numeric or value error"}
								}
							}
						case Blob:
							if val.locator == nil {
								row[colIndex] = nil
							} else {
								tempVal, err := stmt.readLob(col, val.locator)
								if err != nil {
									return err
								}
								if byteVal, ok := tempVal.([]byte); ok {
									row[colIndex] = byteVal
								} else {
									return &network.OracleError{ErrCode: 6502, ErrMsg: "numeric or value error"}
								}
							}
						}
					}
				}
			}
		}
	}
	return nil
}

// requestCustomTypeInfo an experimental function to ask for UDT information
func (stmt *defaultStmt) requestCustomTypeInfo(typeName string) error {
	session := stmt.connection.session
	session.SaveState(nil)
	session.PutBytes(0x3, 0x5c, 0)
	session.PutInt(3, 4, true, true)
	//session.PutInt(0x5C0003, 4, true, true)
	//session.PutBytes(bytes.Repeat([]byte{0}, 79)...)

	session.PutBytes(bytes.Repeat([]byte{0}, 19)...)
	session.PutInt(2, 4, true, true)
	//session.PutBytes(2)
	session.PutInt(len(stmt.connection.connOption.UserID), 4, true, true)
	//session.PutBytes(0, 0, 0)
	session.PutClr(stmt.connection.strConv.Encode(stmt.connection.connOption.UserID))
	session.PutInt(len(typeName), 4, true, true)
	//session.PutBytes(0, 0, 0)
	session.PutClr(stmt.connection.strConv.Encode(typeName))
	//session.PutBytes(0, 0, 0)
	//if session.TTCVersion >= 4 {
	//	session.PutBytes(0, 0, 1)
	//}
	//if session.TTCVersion >= 5 {
	//	session.PutBytes(0, 0, 0, 0, 0)
	//}
	//if session.TTCVersion >= 7 {
	//	if stmt.stmtType == DML && stmt.arrayBindCount > 0 {
	//		session.PutBytes(1)
	//		session.PutInt(stmt.arrayBindCount, 4, true, true)
	//		session.PutBytes(1)
	//	} else {
	//		session.PutBytes(0, 0, 0)
	//	}
	//}
	//if session.TTCVersion >= 8 {
	//	session.PutBytes(0, 0, 0, 0, 0)
	//}
	//if session.TTCVersion >= 9 {
	//	session.PutBytes(0, 0)
	//}
	//session.PutBytes(0, 0)
	//session.PutInt(1, 4, true, true)
	//session.PutBytes(0)
	session.PutBytes(0, 0, 0, 0, 0, 1, 0, 0, 0, 0)
	session.PutBytes(bytes.Repeat([]byte{0}, 50)...)
	//session.PutBytes(0)
	//session.PutInt(0x10000, 4, true, true)
	//session.PutBytes(0, 0)
	err := session.Write()
	if err != nil {
		return err
	}
	data, err := session.GetBytes(0x10)
	if err != nil {
		return err
	}
	fmt.Printf("%#v\n", data)
	session.LoadState()
	return nil
}

func (stmt *defaultStmt) calculateColumnValue(col *ParameterInfo) error {
	session := stmt.connection.session
	//if col.DataType == OCIBlobLocator || col.DataType == OCIClobLocator {
	//	stmt._hasBLOB = true
	//}
	if col.DataType == XMLType {
		if col.TypeName == "XMLTYPE" {
			return errors.New("unsupported data type: XMLTYPE")
		}
		if col.cusType == nil {
			return fmt.Errorf("unregister custom type: %s. call RegisterType first", col.TypeName)
		}
		_, err := session.GetDlc() // contian toid and some 0s
		if err != nil {
			return err
		}
		_, err = session.GetBytes(3) // 3 0s
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
		_, err = session.GetByte()
		if err != nil {
			return err
		}
		tempBytes, err := session.GetClr()
		if err != nil {
			return err
		}
		newState := network.SessionState{InBuffer: tempBytes}
		session.SaveState(&newState)
		_, err = session.GetByte()
		if err != nil {
			return err
		}
		ctl, err := session.GetInt(4, true, true)
		if err != nil {
			return err
		}
		if ctl == 0xFE {
			_, err = session.GetInt(4, false, true)
			if err != nil {
				return err
			}
		}
		for x := 0; x < len(col.cusType.attribs); x++ {
			err = stmt.calculateColumnValue(&col.cusType.attribs[x])
			if err != nil {
				return err
			}
		}
		_ = session.LoadState()
		paramValue := reflect.ValueOf(col.Value)
		if paramValue.Kind() == reflect.Ptr {
			paramValue.Elem().Set(reflect.ValueOf(col.cusType.getObject()))
		} else {
			col.Value = col.cusType.getObject()
		}
		return nil
	}
	return col.decodeColumnValue(stmt.connection)
}

// get values of rows and output parameter according to DataType and binary value (bValue)
func (stmt *defaultStmt) calculateParameterValue(param *ParameterInfo) error {
	session := stmt.connection.session
	if param.DataType == OCIBlobLocator || param.DataType == OCIClobLocator {
		stmt._hasBLOB = true
	}
	if param.DataType == XMLType {
		if param.TypeName == "XMLTYPE" {
			return errors.New("unsupported data type: XMLTYPE")
		}
		if param.cusType == nil {
			return fmt.Errorf("unregister custom type: %s. call RegisterType first", param.TypeName)
		}
		_, err := session.GetDlc() // contian toid and some 0s
		if err != nil {
			return err
		}
		_, err = session.GetBytes(3) // 3 0s
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
		_, err = session.GetByte()
		if err != nil {
			return err
		}
		tempBytes, err := session.GetClr()
		if err != nil {
			return err
		}
		newState := network.SessionState{InBuffer: tempBytes}
		session.SaveState(&newState)
		_, err = session.GetByte()
		if err != nil {
			return err
		}
		ctl, err := session.GetInt(4, true, true)
		if err != nil {
			return err
		}
		if ctl == 0xFE {
			_, err = session.GetInt(4, false, true)
			if err != nil {
				return err
			}
		}
		for x := 0; x < len(param.cusType.attribs); x++ {
			err = stmt.calculateParameterValue(&param.cusType.attribs[x])
			if err != nil {
				return err
			}
		}
		_ = session.LoadState()
		paramValue := reflect.ValueOf(param.Value)
		if paramValue.Kind() == reflect.Ptr {
			paramValue.Elem().Set(reflect.ValueOf(param.cusType.getObject()))
		} else {
			param.Value = param.cusType.getObject()
		}
		return nil
	}
	if param.MaxNoOfArrayElements > 0 {
		size, err := session.GetInt(4, true, true)
		if err != nil {
			return err
		}
		if size > 0 {
			values := make([]driver.Value, size)
			for x := 0; x < size; x++ {
				//param.BValue, err = session.GetClr()
				//if err != nil {
				//	return err
				//}
				// last unused integer is reader outside this function

				values[x], err = param.decodeValue(stmt.connection)
				if x < size-1 {
					_, err = session.GetInt(2, true, true)
				}
				if err != nil {
					return err
				}
			}
			err = param.setParameterArrayValue(values)
			if err != nil {
				return err
			}
		}
		return nil
	}
	return param.decodeParameterValue(stmt.connection)
}

// Close close stmt cursor in the server
func (stmt *defaultStmt) Close() error {
	if stmt.connection.State != Opened {
		return &network.OracleError{ErrCode: 6413, ErrMsg: "ORA-06413: Connection not open"}
	}
	if stmt.cursorID != 0 {
		session := stmt.connection.session
		session.ResetBuffer()
		session.PutBytes(17, 105, 0, 1, 1, 1)
		session.PutInt(stmt.cursorID, 4, true, true)
		return (&simpleObject{
			connection:  stmt.connection,
			operationID: 0x93,
			data:        nil,
			err:         nil,
		}).write().read()
	}
	return nil
}

func (stmt *Stmt) ExecContext(ctx context.Context, namedArgs []driver.NamedValue) (driver.Result, error) {
	if stmt.connection.State != Opened {
		return nil, &network.OracleError{ErrCode: 6413, ErrMsg: "ORA-06413: Connection not open"}
	}
	stmt.connection.connOption.Tracer.Printf("Exec With Context:")
	args := make([]driver.Value, len(namedArgs))
	for x := 0; x < len(args); x++ {
		args[x] = namedArgs[x].Value
	}
	stmt.connection.session.StartContext(ctx)
	defer stmt.connection.session.EndContext()
	return stmt.Exec(args)
}

// Exec execute stmt (INSERT, UPDATE, DELETE, DML, PLSQL) and return driver.Result object
func (stmt *Stmt) Exec(args []driver.Value) (driver.Result, error) {
	if stmt.connection.State != Opened {
		return nil, &network.OracleError{ErrCode: 6413, ErrMsg: "ORA-06413: Connection not open"}
	}
	stmt.connection.connOption.Tracer.Printf("Exec:\n%s", stmt.text)
	var err error

	for x := 0; x < len(args); x++ {
		var par *ParameterInfo
		switch tempOut := args[x].(type) {
		case sql.Out:
			par, err = stmt.NewParam("", tempOut.Dest, 0, Output)
			if err != nil {
				return nil, err
			}
		case *sql.Out:
			par, err = stmt.NewParam("", tempOut.Dest, 0, Output)
			if err != nil {
				return nil, err
			}
		case Out:
			par, err = stmt.NewParam("", tempOut.Dest, tempOut.Size, Output)
			if err != nil {
				return nil, err
			}
		case *Out:
			par, err = stmt.NewParam("", tempOut.Dest, tempOut.Size, Output)
			if err != nil {
				return nil, err
			}
		default:
			par, err = stmt.NewParam("", args[x], 0, Input)
			if err != nil {
				return nil, err
			}
		}
		if x < len(stmt.Pars) {
			if par.MaxLen > stmt.Pars[x].MaxLen {
				stmt.reSendParDef = true
			}
			stmt.Pars[x] = *par
		} else {
			stmt.Pars = append(stmt.Pars, *par)
		}
		stmt.connection.connOption.Tracer.Printf("    %d:\n%v", x, args[x])
	}
	defer func() {
		_ = stmt.freeTemporaryLobs()
	}()
	session := stmt.connection.session
	//if len(args) > 0 {
	//	stmt.Pars = nil
	//}
	//for x := 0; x < len(args); x++ {
	//	stmt.AddParam("", args[x], 0, Input)
	//}
	session.ResetBuffer()
	err = stmt.write(session)
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

func (stmt *Stmt) CheckNamedValue(named *driver.NamedValue) error {
	return nil
}

func (stmt *Stmt) NewParam(name string, val driver.Value, size int, direction ParameterDirection) (*ParameterInfo, error) {
	if stmt.connection.State != Opened {
		return nil, &network.OracleError{ErrCode: 6413, ErrMsg: "ORA-06413: Connection not open"}
	}
	param := &ParameterInfo{
		Name:        name,
		Direction:   direction,
		Flag:        3,
		CharsetID:   stmt.connection.tcpNego.ServerCharset,
		CharsetForm: 1,
	}
	err := param.encodeValue(val, size, stmt.connection)
	if err != nil {
		return nil, err
	}
	if param.Direction == Output {
		param.BValue = nil
	}
	return param, err
}

func (stmt *Stmt) setParam(pos int, par ParameterInfo) {
	if pos >= 0 && pos < len(stmt.Pars) {
		if par.MaxLen > stmt.Pars[pos].MaxLen {
			stmt.reSendParDef = true
		}
		stmt.Pars[pos] = par
	} else {
		stmt.Pars = append(stmt.Pars, par)
	}
}

// AddParam create new parameter and append it to stmt.Pars
func (stmt *Stmt) AddParam(name string, val driver.Value, size int, direction ParameterDirection) error {
	par, err := stmt.NewParam(name, val, size, direction)
	if err != nil {
		return err
	}
	stmt.setParam(-1, *par)
	return nil
	//stmt.Pars = append(stmt.Pars, )
}

// AddRefCursorParam add new output parameter of type REFCURSOR
//
// note: better to use sql.Out structure see examples for more information
func (stmt *Stmt) AddRefCursorParam(name string) {
	par, _ := stmt.NewParam(name, new(RefCursor), 0, Output)
	stmt.Pars = append(stmt.Pars, *par)
}

// Query_ execute a query command and return oracle dataset object
//
// args is an array of values that corresponding to parameters in sql
func (stmt *Stmt) Query_(args []driver.Value) (*DataSet, error) {
	if stmt.connection.State != Opened {
		return nil, &network.OracleError{ErrCode: 6413, ErrMsg: "ORA-06413: Connection not open"}
	}
	result, err := stmt.Query(args)
	if err != nil {
		return nil, err
	}
	if dataSet, ok := result.(*DataSet); ok {
		return dataSet, nil
	}
	return nil, errors.New("the returned driver.rows is not an oracle DataSet")
}

func (stmt *Stmt) QueryContext(ctx context.Context, namedArgs []driver.NamedValue) (driver.Rows, error) {
	if stmt.connection.State != Opened {
		return nil, &network.OracleError{ErrCode: 6413, ErrMsg: "ORA-06413: Connection not open"}
	}
	stmt.connection.connOption.Tracer.Printf("Query With Context:", stmt.text)
	args := make([]driver.Value, len(namedArgs))
	for x := 0; x < len(args); x++ {
		args[x] = namedArgs[x].Value
	}
	stmt.connection.session.StartContext(ctx)
	defer stmt.connection.session.EndContext()
	return stmt.Query(args)
}

// Query execute a query command and return dataset object in form of driver.Rows interface
//
// args is an array of values that corresponding to parameters in sql
func (stmt *Stmt) Query(args []driver.Value) (driver.Rows, error) {
	if stmt.connection.State != Opened {
		return nil, &network.OracleError{ErrCode: 6413, ErrMsg: "ORA-06413: Connection not open"}
	}
	stmt.connection.connOption.Tracer.Printf("Query:\n%s", stmt.text)
	stmt._noOfRowsToFetch = stmt.connection.connOption.PrefetchRows
	//stmt._noOfRowsToFetch = 25
	stmt._hasMoreRows = true
	for x := 0; x < len(args); x++ {
		par, err := stmt.NewParam("", args[x], 0, Input)
		if err != nil {
			return nil, err
		}
		stmt.setParam(x, *par)
	}
	stmt.connection.session.ResetBuffer()

	err := stmt.write(stmt.connection.session)
	if err != nil {
		return nil, err
	}
	dataSet := new(DataSet)
	err = stmt.read(dataSet)
	if err != nil {
		return nil, err
	}
	return dataSet, nil
}

func (stmt *Stmt) NumInput() int {
	return -1
}

/*
parse = true
execute = true
fetch = true if hasReturn or PLSQL
define = false
*/

//func ReadFromExternalBuffer(buffer []byte) error {
//	connOption := &network.ConnectionOption{
//		Port:                  0,
//		TransportConnectTo:    0,
//		SSLVersion:            "",
//		WalletDict:            "",
//		TransportDataUnitSize: 0,
//		SessionDataUnitSize:   0,
//		Protocol:              "",
//		Host:                  "",
//		UserID:                "",
//		SID:                   "",
//		ServiceName:           "",
//		InstanceName:          "",
//		DomainName:            "",
//		DBName:                "",
//		ClientData:            network.ClientData{},
//		Tracer:                trace.NilTracer(),
//		SNOConfig:             nil,
//	}
//	conn := &Connection {
//		State:             Opened,
//		LogonMode:         0,
//		SessionProperties: nil,
//		connOption: connOption,
//	}
//	conn.session = &network.Session{
//		Context:         nil,
//		Summary:         nil,
//		UseBigClrChunks: true,
//		ClrChunkSize:    0x40,
//	}
//	conn.strConv = converters.NewStringConverter(871)
//	conn.session.StrConv = conn.strConv
//	conn.session.FillInBuffer(buffer)
//	conn.session.TTCVersion = 11
//	stmt := &Stmt{
//		defaultStmt:  defaultStmt{
//			connection: conn,
//			scnForSnapshot: make([]int, 2),
//		},
//		reSendParDef: false,
//		parse:        true,
//		execute:      true,
//		define:       false,
//	}
//	dataSet := new(DataSet)
//	err := stmt.read(dataSet)
//	return err
//}
