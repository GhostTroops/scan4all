package network

type OracleError struct {
	ErrCode int
	ErrMsg  string
}

func (err *OracleError) Error() string {
	return err.ErrMsg
}

func (err *OracleError) translate() {
	switch err.ErrCode {
	case 1:
		err.ErrMsg = "ORA-00001: Unique constraint violation"
	case 900:
		err.ErrMsg = "ORA-00900: Invalid SQL statement"
	case 901:
		err.ErrMsg = "ORA-00901: Invalid CREATE command"
	case 902:
		err.ErrMsg = "ORA-00902: Invalid data type"
	case 903:
		err.ErrMsg = "ORA-00903: Invalid table name"
	case 904:
		err.ErrMsg = "ORA-00904: Invalid identifier"
	case 905:
		err.ErrMsg = "ORA-00905: Misspelled keyword"
	case 906:
		err.ErrMsg = "ORA-00906: Missing left parenthesis"
	case 907:
		err.ErrMsg = "ORA-00907: Missing right parenthesis"
	case 12564:
		err.ErrMsg = "ORA-12564: TNS connection refused"
	case 12514:
		err.ErrMsg = "ORA-12514: TNS:listener does not currently know of service requested in connect descriptor"
	default:
		err.ErrMsg = ""
	}
}
