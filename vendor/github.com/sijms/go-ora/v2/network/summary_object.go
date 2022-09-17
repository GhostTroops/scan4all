package network

type BindError struct {
	errorCode int
	rowOffset int
	errorMsg  []byte
}
type SummaryObject struct {
	EndOfCallStatus      int // uint32
	EndToEndECIDSequence int // uint16
	CurRowNumber         int // uint32
	RetCode              int // uint16
	arrayElmWError       int // uint16
	arrayElmErrno        int //uint16
	CursorID             int // uint16
	errorPos             int // uint16
	sqlType              uint8
	oerFatal             uint8
	Flags                int // uint16
	userCursorOPT        int // uint16
	upiParam             uint8
	warningFlag          uint8
	rba                  int // uint32
	partitionID          int // uint16
	tableID              uint8
	blockNumber          int // uint32
	slotNumber           int // uint16
	osError              int // uint32
	stmtNumber           uint8
	callNumber           uint8
	pad1                 int // uint16
	successIter          int // uint16
	ErrorMessage         []byte
	bindErrors           []BindError
}

func NewSummary(session *Session) (*SummaryObject, error) {
	result := new(SummaryObject)
	var err error
	if session.HasEOSCapability {
		result.EndOfCallStatus, err = session.GetInt(4, true, true)
		if err != nil {
			return nil, err
		}
	}
	if session.TTCVersion >= 3 {
		if session.HasFSAPCapability {
			result.EndToEndECIDSequence, err = session.GetInt(2, true, true)
			if err != nil {
				return nil, err
			}
		}
	}
	result.CurRowNumber, err = session.GetInt(4, true, true)
	if err != nil {
		return nil, err
	}
	result.RetCode, err = session.GetInt(2, true, true)
	if err != nil {
		return nil, err
	}
	result.arrayElmWError, err = session.GetInt(2, true, true)
	if err != nil {
		return nil, err
	}
	result.arrayElmErrno, err = session.GetInt(2, true, true)
	if err != nil {
		return nil, err
	}
	result.CursorID, err = session.GetInt(2, true, true)
	if err != nil {
		return nil, err
	}
	result.errorPos, err = session.GetInt(2, true, true)
	if err != nil {
		return nil, err
	}
	result.sqlType, err = session.GetByte()
	if err != nil {
		return nil, err
	}
	result.oerFatal, err = session.GetByte()
	if err != nil {
		return nil, err
	}
	if session.TTCVersion >= 7 {
		result.Flags, err = session.GetInt(2, true, true)
		if err != nil {
			return nil, err
		}
		result.userCursorOPT, err = session.GetInt(2, true, true)
		if err != nil {
			return nil, err
		}
	} else {
		var temp uint8
		temp, err = session.GetByte()
		if err != nil {
			return nil, err
		}
		result.Flags = int(temp)
		temp, err = session.GetByte()
		if err != nil {
			return nil, err
		}
		result.userCursorOPT = int(temp)
	}
	result.upiParam, err = session.GetByte()
	if err != nil {
		return nil, err
	}
	result.warningFlag, err = session.GetByte()
	if err != nil {
		return nil, err
	}
	result.rba, err = session.GetInt(4, true, true)
	if err != nil {
		return nil, err
	}
	result.partitionID, err = session.GetInt(2, true, true)
	if err != nil {
		return nil, err
	}
	result.tableID, err = session.GetByte()
	if err != nil {
		return nil, err
	}
	result.blockNumber, err = session.GetInt(4, true, true)
	if err != nil {
		return nil, err
	}
	result.slotNumber, err = session.GetInt(2, true, true)
	if err != nil {
		return nil, err
	}
	result.osError, err = session.GetInt(4, true, true)
	if err != nil {
		return nil, err
	}
	result.stmtNumber, err = session.GetByte()
	if err != nil {
		return nil, err
	}
	result.callNumber, err = session.GetByte()
	if err != nil {
		return nil, err
	}
	result.pad1, err = session.GetInt(2, true, true)
	if err != nil {
		return nil, err
	}
	result.successIter, err = session.GetInt(4, true, true)
	if err != nil {
		return nil, err
	}
	_, _ = session.GetDlc()
	if session.TTCVersion < 7 {
		_, _ = session.GetDlc()
		_, _ = session.GetDlc()
		_, _ = session.GetDlc()
	} else {
		length, err := session.GetInt(2, true, true)
		if err != nil {
			return nil, err
		}
		if length > 0 {
			result.bindErrors = make([]BindError, length)
			num, err := session.GetByte()
			if err != nil {
				return nil, err
			}
			flag := num == 0xFE
			for x := 0; x < length; x++ {
				if flag {
					if session.UseBigClrChunks {
						_, _ = session.GetInt(4, true, true)
					} else {
						_, _ = session.GetByte()
					}
				}
				result.bindErrors[x].errorCode, err = session.GetInt(2, true, true)
				if err != nil {
					return nil, err
				}
			}
			if flag {
				_, _ = session.GetByte()
			}
		}
		length, err = session.GetInt(4, true, true)
		if err != nil {
			return nil, err
		}
		if length > 0 {
			if len(result.bindErrors) == 0 {
				result.bindErrors = make([]BindError, length)
			}
			num, err := session.GetByte()
			if err != nil {
				return nil, err
			}
			flag := num == 0xFE
			for x := 0; x < length; x++ {
				if flag {
					if session.UseBigClrChunks {
						_, _ = session.GetInt(4, true, true)
					} else {
						_, _ = session.GetByte()
					}
				}
				result.bindErrors[x].rowOffset, err = session.GetInt(4, true, true)
				if err != nil {
					return nil, err
				}
			}
			if flag {
				_, _ = session.GetByte()
			}
		}
		length, err = session.GetInt(2, true, true)
		if err != nil {
			return nil, err
		}
		if length > 0 {
			if len(result.bindErrors) == 0 {
				result.bindErrors = make([]BindError, length)
			}
			_, _ = session.GetByte()
			for x := 0; x < length; x++ {
				_, err := session.GetInt(2, true, true)
				if err != nil {
					return nil, err
				}
				result.bindErrors[x].errorMsg, err = session.GetClr()
				if err != nil {
					return nil, err
				}
				_, _ = session.GetByte()
				_, _ = session.GetByte()
			}
		}
		if session.TTCVersion >= 7 {
			result.RetCode, err = session.GetInt(4, true, true)
			if err != nil {
				return nil, err
			}
			result.CurRowNumber, err = session.GetInt(8, true, true)
			if err != nil {
				return nil, err
			}
		}
	}
	if result.RetCode != 0 {
		result.ErrorMessage, err = session.GetClr()
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

type WarningObject struct {
	retCode      int
	flag         int
	errorMessage string
}

func NewWarningObject(session *Session) (*WarningObject, error) {
	result := new(WarningObject)
	var err error
	result.retCode, err = session.GetInt(2, true, true)
	if err != nil {
		return nil, err
	}
	length, err := session.GetInt(2, true, true)
	if err != nil {
		return nil, err
	}
	result.flag, err = session.GetInt(2, true, true)
	if err != nil {
		return nil, err
	}
	if result.retCode == 0 || length == 0 {
		return nil, nil
	} else {
		msg, err := session.GetClr()
		if err != nil {
			return nil, err
		}
		result.errorMessage = string(msg)
	}
	return result, nil
}
