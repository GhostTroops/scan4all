package go_ora

type RefCursor struct {
	defaultStmt
	len        uint8
	MaxRowSize int
	parent     *defaultStmt
}

func (cursor *RefCursor) load() error {
	// initialize ref cursor object
	cursor.text = ""
	cursor._hasLONG = false
	cursor._hasBLOB = false
	cursor._hasReturnClause = false
	cursor.disableCompression = true
	cursor.arrayBindCount = 1
	cursor.scnForSnapshot = make([]int, 2)
	cursor.stmtType = SELECT
	session := cursor.connection.session
	var err error
	cursor.len, err = session.GetByte()
	if err != nil {
		return err
	}
	cursor.MaxRowSize, err = session.GetInt(4, true, true)
	if err != nil {
		return err
	}
	columnCount, err := session.GetInt(4, true, true)
	if err != nil {
		return err
	}
	if columnCount > 0 {
		cursor.columns = make([]ParameterInfo, columnCount)
		_, err = session.GetByte()
		if err != nil {
			return err
		}
		for x := 0; x < len(cursor.columns); x++ {
			err = cursor.columns[x].load(cursor.connection)
			if err != nil {
				return err
			}
		}
	}
	_, err = session.GetDlc()
	if err != nil {
		return err
	}
	if session.TTCVersion >= 3 {
		_, err = session.GetInt(4, true, true)
		if err != nil {
			return err
		}
		_, err = session.GetInt(4, true, true)
		if err != nil {
			return err
		}
	}
	if session.TTCVersion >= 4 {
		_, err = session.GetInt(4, true, true)
		if err != nil {
			return err
		}
		_, err = session.GetInt(4, true, true)
		if err != nil {
			return err
		}
	}
	if session.TTCVersion >= 5 {
		_, err = session.GetDlc()
		if err != nil {
			return err
		}
	}
	cursor.cursorID, err = session.GetInt(4, true, true)
	if err != nil {
		return err
	}
	_, err = session.GetInt(2, true, true)
	if err != nil {
		return err
	}
	return nil
}
func (cursor *RefCursor) getExeOptions() int {
	return 0x8040
}
func (cursor *RefCursor) Query() (*DataSet, error) {
	cursor.connection.connOption.Tracer.Printf("Query RefCursor: %d", cursor.cursorID)
	cursor._noOfRowsToFetch = cursor.connection.connOption.PrefetchRows
	cursor._hasMoreRows = true
	if len(cursor.parent.scnForSnapshot) > 0 {
		copy(cursor.scnForSnapshot, cursor.parent.scnForSnapshot)
	}
	session := cursor.connection.session
	session.ResetBuffer()
	err := cursor.write()
	if err != nil {
		return nil, err
	}
	dataSet := new(DataSet)
	err = cursor.read(dataSet)
	if err != nil {
		return nil, err
	}
	return dataSet, nil
}

func (cursor *RefCursor) write() error {
	err := cursor.basicWrite(cursor.getExeOptions(), false, false)
	if err != nil {
		return err
	}
	return cursor.connection.session.Write()
}
