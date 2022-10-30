package core

import (
	"encoding/hex"
	"fmt"
	"github.com/hktalent/jaeles/sender"
	"github.com/hktalent/jaeles/utils"
	"github.com/thoas/go-funk"
	"regexp"
	"strconv"
	"strings"

	"github.com/robertkrimen/otto"
)

func (r *Record) Detector() {
	if r.Opt.InlineDetection != "" {
		r.Request.Detections = append(r.Request.Detections, r.Opt.InlineDetection)
	}
	r.RequestScripts("detections", r.Request.Detections)
}

// RequestScripts is main function for detections
func (r *Record) RequestScripts(scriptType string, scripts []string) bool {
	/* Analyze part */
	if r.Request.Beautify == "" {
		r.Request.Beautify = sender.BeautifyRequest(r.Request)
	}
	if len(scripts) <= 0 {
		return false
	}

	record := *r
	var extra string
	vm := otto.New()

	// ExecCmd execute command command
	vm.Set("ExecCmd", func(call otto.FunctionCall) otto.Value {
		result, _ := vm.ToValue(Execution(call.Argument(0).String()))
		return result
	})

	// Component get component content
	vm.Set("Component", func(call otto.FunctionCall) otto.Value {
		componentName := call.Argument(0).String()
		content := GetComponent(record, componentName)
		fmt.Println(content)
		result, _ := vm.ToValue(true)
		return result
	})

	vm.Set("PrintVarf", func(call otto.FunctionCall) otto.Value {
		varName := call.Argument(0).String()
		fmt.Println(record.Request.Target[varName])
		result, _ := vm.ToValue(true)
		return result
	})

	// Printf print ouf some value, useful for debug
	vm.Set("Printf", func(call otto.FunctionCall) otto.Value {
		var err error
		args := call.ArgumentList
		componentName := args[0].String()
		grepString := "**"
		position := 0
		if len(args) > 1 {
			grepString = args[1].String()
			if len(args) > 2 {
				position, err = strconv.Atoi(args[2].String())
				if err != nil {
					position = 0
				}
			}
		}
		component := GetComponent(record, componentName)
		if grepString != "**" {
			r, rerr := regexp.Compile(grepString)
			if rerr == nil {
				matches := r.FindStringSubmatch(component)
				if len(matches) > 0 {
					if position <= len(matches) {
						component = matches[position]
					} else {
						component = matches[0]
					}
				}
			}
		}
		fmt.Println(component)
		result, _ := vm.ToValue(true)
		return result
	})

	// do passive if detections is true
	vm.Set("DoPassive", func(call otto.FunctionCall) otto.Value {
		args := call.ArgumentList
		if len(args) > 0 {
			extra = call.Argument(0).String()
		}
		result, _ := vm.ToValue(true)
		return result
	})

	// return if record is vulnerable or not
	vm.Set("IsVulnerable", func(call otto.FunctionCall) otto.Value {
		result, _ := vm.ToValue(r.IsVulnerable)
		return result
	})

	// shortcut for grepping commong error
	vm.Set("CommonError", func(call otto.FunctionCall) otto.Value {
		args := call.ArgumentList
		componentName := "response"
		if len(args) >= 1 {
			componentName = args[0].String()
		}
		component := GetComponent(record, componentName)
		matched, validate := CommonError(component)
		if extra != "" {
			extra = matched
		}
		result, _ := vm.ToValue(validate)
		return result
	})

	vm.Set("StringGrepCmd", func(call otto.FunctionCall) otto.Value {
		command := call.Argument(0).String()
		searchString := call.Argument(0).String()
		result, _ := vm.ToValue(StringSearch(Execution(command), searchString))
		return result
	})

	vm.Set("RegexGrepCmd", func(call otto.FunctionCall) otto.Value {
		command := call.Argument(0).String()
		searchString := call.Argument(0).String()
		_, validate := RegexSearch(Execution(command), searchString)
		result, _ := vm.ToValue(validate)
		return result
	})

	vm.Set("StringSearch", func(call otto.FunctionCall) otto.Value {
		args := call.ArgumentList
		componentName := "response"
		analyzeString := args[0].String()
		if len(args) >= 2 {
			componentName = args[0].String()
			analyzeString = args[1].String()
		}
		component := GetComponent(record, componentName)
		validate := StringSearch(component, analyzeString)
		result, _ := vm.ToValue(validate)
		return result
	})

	vm.Set("search", func(call otto.FunctionCall) otto.Value {
		args := call.ArgumentList
		componentName := "response"
		analyzeString := args[0].String()
		if len(args) >= 2 {
			componentName = args[0].String()
			analyzeString = args[1].String()
		}
		component := GetComponent(record, componentName)
		validate := StringSearch(component, analyzeString)
		result, _ := vm.ToValue(validate)
		return result
	})

	vm.Set("StringCount", func(call otto.FunctionCall) otto.Value {
		componentName := call.Argument(0).String()
		analyzeString := call.Argument(1).String()
		component := GetComponent(record, componentName)
		validate := StringCount(component, analyzeString)
		result, _ := vm.ToValue(validate)
		return result
	})

	vm.Set("RegexSearch", func(call otto.FunctionCall) otto.Value {
		args := call.ArgumentList
		componentName := "response"
		analyzeString := args[0].String()
		if len(args) >= 2 {
			componentName = args[0].String()
			analyzeString = args[1].String()
		}
		component := GetComponent(record, componentName)
		matches, validate := RegexSearch(component, analyzeString)
		result, err := vm.ToValue(validate)
		if err != nil {
			utils.ErrorF("Error Regex: %v", analyzeString)
			result, _ = vm.ToValue(false)
		}
		if matches != "" {
			extra = matches
		}
		return result
	})

	vm.Set("RegexCount", func(call otto.FunctionCall) otto.Value {
		componentName := call.Argument(0).String()
		analyzeString := call.Argument(1).String()
		component := GetComponent(record, componentName)
		validate := RegexCount(component, analyzeString)
		result, _ := vm.ToValue(validate)
		return result
	})

	vm.Set("StatusCode", func(call otto.FunctionCall) otto.Value {
		statusCode := record.Response.StatusCode
		result, _ := vm.ToValue(statusCode)
		return result
	})
	vm.Set("code", func(call otto.FunctionCall) otto.Value {
		statusCode := record.Response.StatusCode
		result, _ := vm.ToValue(statusCode)
		return result
	})

	vm.Set("ResponseTime", func(call otto.FunctionCall) otto.Value {
		responseTime := record.Response.ResponseTime
		result, _ := vm.ToValue(responseTime)
		return result
	})
	vm.Set("time", func(call otto.FunctionCall) otto.Value {
		responseTime := record.Response.ResponseTime
		result, _ := vm.ToValue(responseTime)
		return result
	})
	vm.Set("ContentLength", func(call otto.FunctionCall) otto.Value {
		args := call.ArgumentList
		if len(args) == 0 {
			ContentLength := record.Response.Length
			result, _ := vm.ToValue(ContentLength)
			return result
		}
		componentName := args[0].String()
		componentLength := len(GetComponent(record, componentName))
		result, _ := vm.ToValue(componentLength)
		return result
	})

	vm.Set("HasPopUp", func(call otto.FunctionCall) otto.Value {
		result, _ := vm.ToValue(record.Response.HasPopUp)
		return result
	})

	// if checksum is different with all previous checksum
	vm.Set("Diff", func(call otto.FunctionCall) otto.Value {
		rchecksum := record.Response.Checksum
		isDiff := true
		if funk.ContainsString(record.Sign.Checksums, rchecksum) {
			isDiff = false
		}

		utils.DebugF("Checksums: %v", record.Sign.Checksums)
		utils.DebugF("Current Checksum: %v", rchecksum)
		utils.DebugF("Diff() -- %v", isDiff)

		result, _ := vm.ToValue(isDiff)
		return result
	})

	// Origin field
	vm.Set("OriginStatusCode", func(call otto.FunctionCall) otto.Value {
		statusCode := record.OriginRes.StatusCode
		result, _ := vm.ToValue(statusCode)
		return result
	})
	vm.Set("oCode", func(call otto.FunctionCall) otto.Value {
		statusCode := record.OriginRes.StatusCode
		result, _ := vm.ToValue(statusCode)
		return result
	})
	vm.Set("OriginResponseTime", func(call otto.FunctionCall) otto.Value {
		responseTime := record.OriginRes.ResponseTime
		result, _ := vm.ToValue(responseTime)
		return result
	})
	vm.Set("OriginContentLength", func(call otto.FunctionCall) otto.Value {
		args := call.ArgumentList
		if len(args) == 0 {
			ContentLength := record.OriginRes.Length
			result, _ := vm.ToValue(ContentLength)
			return result
		}
		selectedRec := Record{Request: record.OriginReq, Response: record.OriginRes}
		componentName := args[0].String()
		componentLength := len(GetComponent(selectedRec, componentName))
		result, _ := vm.ToValue(componentLength)
		return result
	})

	// Origins('1', 'status')
	// Origins('response')
	vm.Set("Origins", func(call otto.FunctionCall) otto.Value {
		args := call.ArgumentList
		index := 0
		componentName := args[0].String()
		if len(args) >= 2 {
			index = utils.StrToInt(args[0].String())
			componentName = args[1].String()
		}
		selectedRec := ChooseOrigin(record, index)
		componentName = strings.ToLower(componentName)
		switch componentName {
		case "status":
			value := selectedRec.Response.StatusCode
			result, _ := vm.ToValue(value)
			return result
		case "code":
			value := selectedRec.Response.StatusCode
			result, _ := vm.ToValue(value)
			return result
		case "responsetime":
			value := selectedRec.Response.ResponseTime
			result, _ := vm.ToValue(value)
			return result
		case "time":
			value := selectedRec.Response.ResponseTime
			result, _ := vm.ToValue(value)
			return result
		case "contentlength":
			value := len(selectedRec.Response.Beautify)
			result, _ := vm.ToValue(value)
			return result
		case "length":
			value := len(selectedRec.Response.Beautify)
			result, _ := vm.ToValue(value)
			return result
		}
		// default value
		result, _ := vm.ToValue(true)
		return result
	})

	// OriginSearch('component', 'string')
	// OriginSearch('1', 'component', 'string')
	vm.Set("OriginsSearch", func(call otto.FunctionCall) otto.Value {
		args := call.ArgumentList
		index := 0
		componentName := args[0].String()
		analyzeString := args[1].String()
		if len(args) >= 3 {
			index = utils.StrToInt(args[0].String())
			componentName = args[1].String()
			analyzeString = args[2].String()
		}
		selectedRec := ChooseOrigin(record, index)
		componentName = strings.ToLower(componentName)
		component := GetComponent(selectedRec, componentName)
		validate := StringSearch(component, analyzeString)
		result, _ := vm.ToValue(validate)
		return result
	})
	vm.Set("OriginsRegex", func(call otto.FunctionCall) otto.Value {
		args := call.ArgumentList
		index := 0
		componentName := args[0].String()
		analyzeString := args[1].String()
		if len(args) >= 3 {
			index = utils.StrToInt(args[0].String())
			componentName = args[1].String()
			analyzeString = args[2].String()
		}
		selectedRec := ChooseOrigin(record, index)
		componentName = strings.ToLower(componentName)
		component := GetComponent(selectedRec, componentName)
		matches, validate := RegexSearch(component, analyzeString)
		result, err := vm.ToValue(validate)
		if err != nil {
			utils.ErrorF("Error Regex: %v", analyzeString)
			result, _ = vm.ToValue(false)
		}
		if matches != "" {
			extra = matches
		}
		return result
	})

	//
	//vm.Set("Collab", func(call otto.FunctionCall) otto.Value {
	//	analyzeString := call.Argument(0).String()
	//	res, validate := PollCollab(record, analyzeString)
	//	extra = res
	//	result, _ := vm.ToValue(validate)
	//	return result
	//})

	// StringGrep select a string from component
	// StringGrep("component", "right", "left")
	vm.Set("StringSelect", func(call otto.FunctionCall) otto.Value {
		componentName := call.Argument(0).String()
		left := call.Argument(2).String()
		right := call.Argument(3).String()
		component := GetComponent(record, componentName)
		value := Between(component, left, right)
		result, _ := vm.ToValue(value)
		return result
	})

	//  - RegexGrep("component", "regex")
	//  - RegexGrep("component", "regex", "position")
	vm.Set("RegexGrep", func(call otto.FunctionCall) otto.Value {
		value := RegexGrep(record, call.ArgumentList)
		result, _ := vm.ToValue(value)
		return result
	})

	vm.Set("ValueOf", func(call otto.FunctionCall) otto.Value {
		valueName := call.Argument(0).String()
		utils.DebugF("ValueOf: %v -- %v", valueName, record.Request.Target[valueName])
		if record.Request.Target[valueName] != "" {
			value := record.Request.Target[valueName]
			result, _ := vm.ToValue(value)
			return result
		}
		result, _ := vm.ToValue(false)
		return result
	})

	// check if folder, file exist or not
	vm.Set("Exist", func(call otto.FunctionCall) otto.Value {
		input := utils.NormalizePath(call.Argument(0).String())
		var exist bool
		if utils.FileExists(input) {
			exist = true
		}
		if utils.FolderExists(input) {
			exist = true
		}
		result, _ := vm.ToValue(exist)
		return result
	})

	vm.Set("DirLength", func(call otto.FunctionCall) otto.Value {
		validate := utils.DirLength(call.Argument(0).String())
		result, _ := vm.ToValue(validate)
		return result
	})

	vm.Set("FileLength", func(call otto.FunctionCall) otto.Value {
		validate := utils.FileLength(call.Argument(0).String())
		result, _ := vm.ToValue(validate)
		return result
	})

	/* Really start do detection here */
	switch scriptType {
	case "detect", "detections":
		for _, analyze := range scripts {
			// pass detection here
			result, _ := vm.Run(analyze)
			analyzeResult, err := result.Export()
			// in case vm panic
			if err != nil || analyzeResult == nil {
				r.DetectString = analyze
				r.IsVulnerable = false
				r.DetectResult = ""
				r.ExtraOutput = ""
				continue
			}
			r.DetectString = analyze
			r.IsVulnerable = analyzeResult.(bool)
			r.DetectResult = extra
			r.ExtraOutput = extra

			utils.DebugF("[Detection] %v -- %v", analyze, r.IsVulnerable)
			// deal with vulnerable one here
			next := r.Output()
			if next == "stop" {
				return true
			}
		}
		return r.IsVulnerable
	case "condition", "conditions":
		var valid bool
		for _, analyze := range scripts {
			result, _ := vm.Run(analyze)
			analyzeResult, err := result.Export()
			// in case vm panic
			if err != nil || analyzeResult == nil {
				r.PassCondition = false
				continue
			}
			r.PassCondition = analyzeResult.(bool)
			utils.DebugF("[Condition] %v -- %v", analyze, r.PassCondition)
			valid = r.PassCondition
		}
		return valid
	case "pass", "passive", "passives":
		for _, analyze := range scripts {
			// pass detection here
			result, _ := vm.Run(analyze)
			analyzeResult, err := result.Export()
			// in case vm panic
			if err != nil || analyzeResult == nil {
				r.PassiveString = analyze
				r.IsVulnerablePassive = false
				r.PassiveMatch = ""
				continue
			}
			r.PassiveString = analyze
			r.IsVulnerablePassive = analyzeResult.(bool)
			r.PassiveMatch = extra

			utils.DebugF("[PassiveDetect] %v -- %v", analyze, r.IsVulnerablePassive)
			// deal with vulnerable one here
			next := r.PassiveOutput()
			if next == "stop" {
				return true
			}
		}
		return r.IsVulnerablePassive
	}

	return false
}

//////////////

// ChooseOrigin choose origin to compare
func ChooseOrigin(record Record, index int) Record {
	selectedRec := record
	if len(record.Origins) == 0 || len(record.Origins) < index {
		return selectedRec
	}

	origin := record.Origins[index]
	var compareRecord Record
	compareRecord.Request = origin.ORequest
	compareRecord.Response = origin.OResponse
	selectedRec = compareRecord
	return selectedRec
}

// GetComponent get component to run detection
func GetComponent(record Record, component string) string {
	component = strings.ToLower(component)
	utils.DebugF("Get Component: %v", component)
	switch component {
	case "orequest":

		return record.OriginReq.Beautify
	case "oresheaders", "oheaders", "ohead", "oresheader":
		beautifyHeader := fmt.Sprintf("%v \n", record.OriginRes.Status)
		for _, header := range record.OriginRes.Headers {
			for key, value := range header {
				beautifyHeader += fmt.Sprintf("%v: %v\n", key, value)
			}
		}
		return beautifyHeader
	case "obody", "oresbody":
		return record.OriginRes.Body
	case "oresponse", "ores":
		return record.OriginRes.Beautify
	case "request":
		return record.Request.Beautify
	case "response":
		if record.Response.Beautify == "" {
			return record.Response.Body
		}
		return record.Response.Beautify
	case "resheader", "resheaders", "headers", "header":
		beautifyHeader := fmt.Sprintf("%v \n", record.Response.Status)
		for _, header := range record.Response.Headers {
			for key, value := range header {
				beautifyHeader += fmt.Sprintf("%v: %v\n", key, value)
			}
		}
		return beautifyHeader
	case "body", "resbody":
		return record.Response.Body
	case "bytes", "byte", "hex":
		return hex.EncodeToString([]byte(record.Request.Beautify))
	case "byteBody", "hexBody":
		return hex.EncodeToString([]byte(record.Request.Body))
	case "middleware":
		return record.Request.MiddlewareOutput
	default:
		return record.Response.Beautify
	}
}

// StringSearch search string literal in component
func StringSearch(component string, analyzeString string) bool {
	var result bool
	if strings.Contains(component, analyzeString) {
		result = true
	}
	utils.DebugF("analyzeString: %v -- %v", analyzeString, result)
	return result
}

// StringCount count string literal in component
func StringCount(component string, analyzeString string) int {
	return strings.Count(component, analyzeString)
}

// RegexSearch search regex string in component
func RegexSearch(component string, analyzeString string) (string, bool) {
	var result bool
	var extra string
	r, err := regexp.Compile(analyzeString)
	if err != nil {
		utils.ErrorF("Analyze String Error: %s", analyzeString)
		return extra, result
	}

	matches := r.FindStringSubmatch(component)
	if len(matches) > 0 {
		result = true
		extra = strings.Join(matches, "\n")
	}
	utils.DebugF("Component: %v", component)
	utils.DebugF("analyzeRegex: %v -- %v", analyzeString, result)
	return extra, result
}

// RegexCount count regex string in component
func RegexCount(component string, analyzeString string) int {
	r, err := regexp.Compile(analyzeString)
	if err != nil {
		return 0
	}
	matches := r.FindAllStringIndex(component, -1)
	return len(matches)
}

// RegexGrep grep regex string from component
func RegexGrep(realRec Record, arguments []otto.Value) string {
	componentName := arguments[0].String()
	component := GetComponent(realRec, componentName)

	regexString := arguments[1].String()
	var position int
	var err error
	if len(arguments) > 2 {
		position, err = strconv.Atoi(arguments[2].String())
		if err != nil {
			position = 0
		}
	}

	var value string
	r, rerr := regexp.Compile(regexString)
	if rerr != nil {
		return ""
	}
	matches := r.FindStringSubmatch(component)
	if len(matches) > 0 {
		if position <= len(matches) {
			value = matches[position]
		} else {
			value = matches[0]
		}
	}
	return value
}

// CommonError shortcut for common error
func CommonError(component string) (string, bool) {
	rules := []string{
		`(Exception (condition )?\\d+\\. Transaction rollback|com\\.frontbase\\.jdbc|org\\.h2\\.jdbc|Unexpected end of command in statement \\[\"|Unexpected token.*?in statement \\[|org\\.hsqldb\\.jdbc|CLI Driver.*?DB2|DB2 SQL error|\\bdb2_\\w+\\(|SQLSTATE.+SQLCODE|com\\.ibm\\.db2\\.jcc|Zend_Db_(Adapter|Statement)_Db2_Exception|Pdo[./_\\\\]Ibm|DB2Exception|Warning.*?\\Wifx_|Exception.*?Informix|Informix ODBC Driver|ODBC Informix driver|com\\.informix\\.jdbc|weblogic\\.jdbc\\.informix|Pdo[./_\\\\]Informix|IfxException|Warning.*?\\Wingres_|Ingres SQLSTATE|Ingres\\W.*?Driver|com\\.ingres\\.gcf\\.jdbc|Dynamic SQL Error|Warning.*?\\Wibase_|org\\.firebirdsql\\.jdbc|Pdo[./_\\\\]Firebird|Microsoft Access (\\d+ )?Driver|JET Database Engine|Access Database Engine|ODBC Microsoft Access|Syntax error \\(missing operator\\) in query expression|Driver.*? SQL[\\-\\_\\ ]*Server|OLE DB.*? SQL Server|\\bSQL Server[^&lt;&quot;]+Driver|Warning.*?\\W(mssql|sqlsrv)_|\\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}|System\\.Data\\.SqlClient\\.SqlException|(?s)Exception.*?\\bRoadhouse\\.Cms\\.|Microsoft SQL Native Client error '[0-9a-fA-F]{8}|\\[SQL Server\\]|ODBC SQL Server Driver|ODBC Driver \\d+ for SQL Server|SQLServer JDBC Driver|com\\.jnetdirect\\.jsql|macromedia\\.jdbc\\.sqlserver|Zend_Db_(Adapter|Statement)_Sqlsrv_Exception|com\\.microsoft\\.sqlserver\\.jdbc|Pdo[./_\\\\](Mssql|SqlSrv)|SQL(Srv|Server)Exception|SQL syntax.*?MySQL|Warning.*?\\Wmysqli?_|MySQLSyntaxErrorException|valid MySQL result|check the manual that corresponds to your (MySQL|MariaDB) server version|Unknown column '[^ ]+' in 'field list'|MySqlClient\\.|com\\.mysql\\.jdbc|Zend_Db_(Adapter|Statement)_Mysqli_Exception|Pdo[./_\\\\]Mysql|MySqlException|\\bORA-\\d{5}|Oracle error|Oracle.*?Driver|Warning.*?\\W(oci|ora)_|quoted string not properly terminated|SQL command not properly ended|macromedia\\.jdbc\\.oracle|oracle\\.jdbc|Zend_Db_(Adapter|Statement)_Oracle_Exception|Pdo[./_\\\\](Oracle|OCI)|OracleException|PostgreSQL.*?ERROR|Warning.*?\\Wpg_|valid PostgreSQL result|Npgsql\\.|PG::SyntaxError:|org\\.postgresql\\.util\\.PSQLException|ERROR:\\s\\ssyntax error at or near|ERROR: parser: parse error at or near|PostgreSQL query failed|org\\.postgresql\\.jdbc|Pdo[./_\\\\]Pgsql|PSQLException|SQL error.*?POS([0-9]+)|Warning.*?\\Wmaxdb_|DriverSapDB|com\\.sap\\.dbtech\\.jdbc|SQLite/JDBCDriver|SQLite\\.Exception|(Microsoft|System)\\.Data\\.SQLite\\.SQLiteException|Warning.*?\\W(sqlite_|SQLite3::)|\\[SQLITE_ERROR\\]|SQLite error \\d+:|sqlite3.OperationalError:|SQLite3::SQLException|org\\.sqlite\\.JDBC|Pdo[./_\\\\]Sqlite|SQLiteException|Warning.*?\\Wsybase_|Sybase message|Sybase.*?Server message|SybSQLException|Sybase\\.Data\\.AseClient|com\\.sybase\\.jdbc)`,
		`injectx|stack smashing detected|Backtrace|Memory map|500 Internal Server Error|Set-Cookie:\\scrlf=injection|java\\.io\\.FileNotFoundException|java\\.lang\\.Exception|java\\.lang\\.IllegalArgumentException|java\\.net\\.MalformedURLException|Warning: include\\(|Warning: unlink\\(|for inclusion \\(include_path=|fread\\(|Failed opening required|Warning: file_get_contents\\(|Fatal error: require_once\\(|Warning: file_exists\\(|root:|(uid|gid|groups)=\\d+|bytes from \\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b|Configuration File \\(php\\.ini\\) Path |vulnerable 10|Trying \\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b|\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b\\s+localhost|BROADCAST,MULTICAST|drwxr-xr|Active Internet connections|Syntax error|sh:|Average Speed   Time|dir: cannot access|<script>alert\\(1\\)</script>|drwxrwxr|GNU/Linux|(Exception (condition )?\\d+\\. Transaction rollback|com\\.frontbase\\.jdbc|org\\.h2\\.jdbc|Unexpected end of command in statement \\[\"|Unexpected token.*?in statement \\[|org\\.hsqldb\\.jdbc|CLI Driver.*?DB2|DB2 SQL error|\\bdb2_\\w+\\(|SQLSTATE.+SQLCODE|com\\.ibm\\.db2\\.jcc|Zend_Db_(Adapter|Statement)_Db2_Exception|Pdo[./_\\\\]Ibm|DB2Exception|Warning.*?\\Wifx_|Exception.*?Informix|Informix ODBC Driver|ODBC Informix driver|com\\.informix\\.jdbc|weblogic\\.jdbc\\.informix|Pdo[./_\\\\]Informix|IfxException|Warning.*?\\Wingres_|Ingres SQLSTATE|Ingres\\W.*?Driver|com\\.ingres\\.gcf\\.jdbc|Dynamic SQL Error|Warning.*?\\Wibase_|org\\.firebirdsql\\.jdbc|Pdo[./_\\\\]Firebird|Microsoft Access (\\d+ )?Driver|JET Database Engine|Access Database Engine|ODBC Microsoft Access|Syntax error \\(missing operator\\) in query expression|Driver.*? SQL[\\-\\_\\ ]*Server|OLE DB.*? SQL Server|\\bSQL Server[^&lt;&quot;]+Driver|Warning.*?\\W(mssql|sqlsrv)_|\\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}|System\\.Data\\.SqlClient\\.SqlException|(?s)Exception.*?\\bRoadhouse\\.Cms\\.|Microsoft SQL Native Client error '[0-9a-fA-F]{8}|\\[SQL Server\\]|ODBC SQL Server Driver|ODBC Driver \\d+ for SQL Server|SQLServer JDBC Driver|com\\.jnetdirect\\.jsql|macromedia\\.jdbc\\.sqlserver|Zend_Db_(Adapter|Statement)_Sqlsrv_Exception|com\\.microsoft\\.sqlserver\\.jdbc|Pdo[./_\\\\](Mssql|SqlSrv)|SQL(Srv|Server)Exception|SQL syntax.*?MySQL|Warning.*?\\Wmysqli?_|MySQLSyntaxErrorException|valid MySQL result|check the manual that corresponds to your (MySQL|MariaDB) server version|Unknown column '[^ ]+' in 'field list'|MySqlClient\\.|com\\.mysql\\.jdbc|Zend_Db_(Adapter|Statement)_Mysqli_Exception|Pdo[./_\\\\]Mysql|MySqlException|\\bORA-\\d{5}|Oracle error|Oracle.*?Driver|Warning.*?\\W(oci|ora)_|quoted string not properly terminated|SQL command not properly ended|macromedia\\.jdbc\\.oracle|oracle\\.jdbc|Zend_Db_(Adapter|Statement)_Oracle_Exception|Pdo[./_\\\\](Oracle|OCI)|OracleException|PostgreSQL.*?ERROR|Warning.*?\\Wpg_|valid PostgreSQL result|Npgsql\\.|PG::SyntaxError:|org\\.postgresql\\.util\\.PSQLException|ERROR:\\s\\ssyntax error at or near|ERROR: parser: parse error at or near|PostgreSQL query failed|org\\.postgresql\\.jdbc|Pdo[./_\\\\]Pgsql|PSQLException|SQL error.*?POS([0-9]+)|Warning.*?\\Wmaxdb_|DriverSapDB|com\\.sap\\.dbtech\\.jdbc|SQLite/JDBCDriver|SQLite\\.Exception|(Microsoft|System)\\.Data\\.SQLite\\.SQLiteException|Warning.*?\\W(sqlite_|SQLite3::)|\\[SQLITE_ERROR\\]|SQLite error \\d+:|sqlite3.OperationalError:|SQLite3::SQLException|org\\.sqlite\\.JDBC|Pdo[./_\\\\]Sqlite|SQLiteException|Warning.*?\\Wsybase_|Sybase message|Sybase.*?Server message|SybSQLException|Sybase\\.Data\\.AseClient|com\\.sybase\\.jdbc)|System\\.Xml\\.XPath\\.XPathException|MS\\.Internal\\.Xml|Unknown error in XPath|org\\.apache\\.xpath\\.XPath|A closing bracket expected in|An operand in Union Expression does not produce a node-set|Cannot convert expression to a number|Document Axis does not allow any context Location Steps|Empty Path Expression|DOMXPath|Empty Relative Location Path|Empty Union Expression|Expected \\'\\)\\' in|Expected node test or name specification after axis operator|Incompatible XPath key|Incorrect Variable Binding|libxml2 library function failed|libxml2|Invalid predicate|Invalid expression|xmlsec library function|xmlsec|error \\'80004005\\'|A document must contain exactly one root element|<font face=\"Arial\" size=2>Expression must evaluate to a node-set|Expected token ']'|<p>msxml4\\.dll<\\/font>|<p>msxml3\\.dll<\\/font>|4005 Notes error: Query is not understandable|SimpleXMLElement::xpath|xmlXPathEval:|simplexml_load_string|parser error :|An error occured!|xmlParseEntityDecl|simplexml_load_string|xmlParseInternalSubset|DOCTYPE improperly terminated|Start tag expected|No declaration for attribute|No declaration for element|failed to load external entity|Start tag expected|Invalid URI: file:\\/\\/\\/|Malformed declaration expecting version|Unicode strings with encoding|must be well-formed|Content is not allowed in prolog|org.xml.sax|SAXParseException|com.sun.org.apache.xerces|ParseError|nokogiri|REXML|XML syntax error on line|Error unmarshaling XML|conflicts with field|illegal character code|XML Parsing Error|SyntaxError|no root element|not well-formed\n`,
		`Warning: include\(|Warning: unlink\(|for inclusion \(include_path=|fread\(|Failed opening required|Warning: file_get_contents\(|Fatal error: require_once\(|Warning: file_exists\(`,
		`java\.io\.FileNotFoundException|java\.lang\.Exception|java\.lang\.IllegalArgumentException|java\.net\.MalformedURLException`,
		`simplexml_load_string|parser error :|An error occured!|xmlParseEntityDecl|simplexml_load_string|xmlParseInternalSubset|DOCTYPE improperly terminated|Start tag expected|No declaration for attribute|No declaration for element|failed to load external entity|Start tag expected|Invalid URI: file:\/\/\/|Malformed declaration expecting version|Unicode strings with encoding|must be well-formed|Content is not allowed in prolog|org.xml.sax|SAXParseException|com.sun.org.apache.xerces|ParseError|nokogiri|REXML|XML syntax error on line|Error unmarshaling XML|conflicts with field|illegal character code|XML Parsing Error|SyntaxError|no root element|not well-formed`,
		`root:|(uid|gid|groups)=\d+|bytes from \b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|Configuration File \(php\.ini\) Path |vulnerable 10|Trying \b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b\s+localhost|BROADCAST,MULTICAST|drwxr-xr|Active Internet connections|Syntax error|sh:|Average Speed   Time|dir: cannot access|<script>alert\(1\)</script>|drwxrwxr|GNU/Linux`,
	}
	var result bool
	var extra string

	for _, rule := range rules {
		r, err := regexp.Compile(rule)
		if err != nil {
			return extra, result
		}

		matches := r.FindStringSubmatch(component)
		if len(matches) > 0 {
			result = true
			extra = strings.Join(matches, "\n")
		}
		if result {
			return extra, result

		}
	}
	return extra, result
}

//// @NOTE: deprecated for now
//// PollCollab polling burp collab with secret from DB
//func PollCollab(record Record, analyzeString string) (string, bool) {
//	// only checking response return in external OOB
//	ssrf := database.GetDefaultBurpCollab()
//	if ssrf != "" {
//		res := database.GetDefaultBurpRes()
//		result := StringSearch(record.Response.Beautify, res)
//		return res, result
//	}
//
//	// storing raw here so we can poll later
//	database.ImportReqLog(record, analyzeString)
//	secretCollab := url.QueryEscape(database.GetSecretbyCollab(analyzeString))
//
//	// poll directly
//	burl := fmt.Sprintf("http://polling.burpcollaborator.net/burpresults?biid=%v", secretCollab)
//	_, response, _ := gorequest.New().Get(burl).End()
//	jsonParsed, _ := gabs.ParseJSON([]byte(response))
//	exists := jsonParsed.Exists("responses")
//	if exists == false {
//		data := database.GetOOB(analyzeString)
//		if data != "" {
//			return data, strings.Contains(data, analyzeString)
//		}
//		return "", false
//	}
//
//	// jsonParsed.Path("responses").Children()
//	for _, element := range jsonParsed.Path("responses").Children() {
//		protocol := element.Path("protocol").Data().(string)
//		// import this to DB so we don't miss in other detect
//		database.ImportOutOfBand(fmt.Sprintf("%v", element))
//		if protocol == "http" {
//			interactionString := element.Path("interactionString").Data().(string)
//			return element.String(), strings.Contains(analyzeString, interactionString)
//		} else if protocol == "dns" {
//			interactionString := element.Path("interactionString").Data().(string)
//			return element.String(), strings.Contains(analyzeString, interactionString)
//		}
//	}
//
//	return "", false
//}
