package oracle

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/hktalent/scan4all/pkg/kscan/core/slog"
	_ "github.com/sijms/go-ora/v2"
	"strings"
	"time"
)

var ServiceName = []string{
	"orcl", "XE", "TEST", "RIS", "HIS", "PACS", "ORACLE", "ORACLE10", "ORACLE11", "ORACLEDB",
	"ORA10", "ORA11", "orcl3", "orcl.3", "orcl.1", "LINUX8174", "ASDB", "IASDB", "OEMREP", "CLREXTPROC",
	"SA0", "PLSEXTPROC", "SA1", "SA2", "SA3", "SA4", "SA5", "SA6", "SA7", "SA8",
	"SA9", "SAA", "SAB", "SAC", "SAD", "SAE", "SAF", "SAG", "SAH", "SAI",
	"SAJ", "SAK", "SAL", "SAM", "SAN", "SAO", "SAP", "SAQ", "SAR", "SAS",
	"SAT", "SAU", "SAV", "SAW", "SAX", "SAY", "SAZ", "IXOS", "CTM4_0", "CTM4_1",
	"CTM4_6", "ARIS", "MSAM", "ADV1", "ADVCPROD", "ASDB0", "ASDB1", "ASDB2", "ASDB3", "ASDB4",
	"ASDB5", "ASDB6", "ASDB7", "ASDB8", "ASDB9", "ASG817", "ASG817P", "ASG817T", "ATRPROD", "ATRTEST",
	"BLA", "BUDGET", "C630", "D", "D10", "D8", "D9", "DB", "DB01", "DB02",
	"DB03", "DB1", "DB2", "DB2EDU", "DB2PROD", "DB2TEST", "DB3", "DBA", "DBA1", "DBA2",
	"DBA3", "DBA4", "DBA5", "DBA6", "DBA7", "DBA8", "DBA9", "DBX", "DEMO", "DEV",
	"DEV0", "DEV1", "DEV2", "DEV3", "DEV4", "DEV5", "DEV6", "DEV7", "DEV8", "DEV9",
	"DEVEL", "DIA1", "DIA2", "DIS", "DWH", "DWHPROD", "DWHTEST", "DWRHS", "ELCARO", "EMRS2",
	"EOF", "ESOR", "FINDEC", "FINPROD", "FNDFS_HR1", "FNDFS_HR2", "FPRD", "GR01", "GR02", "GR03",
	"HR", "HR0", "HR1", "HR2", "HR3", "HR4", "HR5", "HR6", "HR7", "HR8",
	"HR9", "HRDMO", "INCD", "ISD01", "ISD06", "ISP01", "ITS", "KRAUS", "KRONOS", "LDAP",
	"LINUX101", "LINUX1011", "LINUX1012", "LINUX1013", "LINUX1014", "LINUX102", "LINUX1021", "LINUX817", "LINUX8171", "LINUX8172",
	"LINUX8173", "LINUX901", "LINUX902", "LINUX9021", "LINUX9022", "LINUX9023", "LINUX9024", "LINUX9025", "LINUX9026", "LINUX9027",
	"LUN", "MDTEST", "MYDB", "NEDB", "NORTHWIND", "ODB", "OGDP", "OID", "OJS", "OMS",
	"ORA1", "ORA101", "ORA10101", "ORA10101P", "ORA10101T", "ORA10102", "ORA10102P", "ORA10102T", "ORA10103", "ORA10103P",
	"ORA10103T", "ORA10104", "ORA10104P", "ORA10104T", "ORA10105", "ORA10105P", "ORA10105T", "ORA1011", "ORA1011P", "ORA1011T",
	"ORA1012", "ORA1012P", "ORA1012T", "ORA1013", "ORA1013P", "ORA1013T", "ORA1014", "ORA1014P", "ORA1014T", "ORA1015",
	"ORA1015P", "ORA1015T", "ORA1021", "ORA1021P", "ORA1021T", "ORA1022", "ORA1022P", "ORA1022T", "ORA2", "ORA8",
	"ORA805", "ORA806", "ORA815", "ORA816", "ORA817", "ORA8170", "ORA8170P", "ORA8170T", "ORA8171", "ORA8171P",
	"ORA8171T", "ORA8172", "ORA8172P", "ORA8172T", "ORA8173", "ORA8173P", "ORA8173T", "ORA8174", "ORA8174P", "ORA8174T",
	"ORA8_SC", "ORA910", "ORA920", "ORA9201", "ORA9201P", "ORA9201T", "ORA9202", "ORA9202P", "ORA9202T", "ORA9203",
	"ORA9203P", "ORA9203T", "ORA9204", "ORA9204P", "ORA9204T", "ORA9205", "ORA9205P", "ORA9205T", "ORA9206", "ORA9206P",
	"ORA9206T", "ORA9207", "ORA9207P", "ORA9207T", "ORACL", "ORADB", "ORADB1", "ORADB2", "ORADB3", "ORALIN",
	"orcl0", "orcl1", "orcl10", "orcl2", "orcl4", "orcl5", "orcl6", "orcl7", "orcl8", "orcl9",
	"orclA", "orclB", "orclC", "orclD", "orclE", "orclF", "orclG", "orclH", "orclI", "orclJ",
	"orclK", "orclL", "orclM", "orclN", "orclO", "orclP", "orclP0", "orclP1", "orclP2", "orclP3",
	"orclP4", "orclP5", "orclP6", "orclP7", "orclP8", "orclP9", "orclQ", "orclR", "orclS", "orclSOL",
	"orclT", "orclU", "orclV", "orclW", "orclX", "orclY", "orclZ", "ORIONDB", "ORTD", "P",
	"P10", "P10G", "P8", "P8I", "P9", "P9I", "PD1", "PINDB", "PORA10101", "PORA10102",
	"PORA10103", "PORA10104", "PORA10105", "PORA1011", "PORA1012", "PORA1013", "PORA1014", "PORA1015", "PORA1021", "PORA1022",
	"PORA8170", "PORA8171", "PORA8172", "PORA8173", "PORA8174", "PORA9201", "PORA9202", "PORA9203", "PORA9204", "PORA9205",
	"PORA9206", "PORA9207", "PRD", "PRITXI", "PROD", "PROD0", "PROD1", "PROD10G", "PROD2", "PROD3",
	"PROD4", "PROD5", "PROD6", "PROD7", "PROD8", "PROD8I", "PROD9", "PROD920", "PROD9I", "PROG10",
	"RAB1", "RAC", "RAC1", "RAC2", "RAC3", "RAC4", "RECV", "REP", "REP0", "REP1",
	"REP2", "REP3", "REP4", "REP5", "REP6", "REP7", "REP8", "REP9", "REPO", "REPO0",
	"REPO1", "REPO2", "REPO3", "REPO4", "REPO5", "REPO6", "REPO7", "REPO8", "REPO9", "REPOS",
	"REPOS0", "REPOS1", "REPOS2", "REPOS3", "REPOS4", "REPOS5", "REPOS6", "REPOS7", "REPOS8", "REPOS9",
	"RIPPROD", "RITCTL", "RITDEV", "RITPROD", "RITQA", "RITTRN", "RITTST", "SALES", "SAMPLE", "SANIPSP",
	"SAP0", "SAP1", "SAP2", "SAP3", "SAP4", "SAP5", "SAP6", "SAP7", "SAP8", "SAP9",
	"SAPHR", "SGNT", "SID0", "SID1", "SID2", "SID3", "SID4", "SID5", "SID6", "SID7",
	"SID8", "SID9", "STAG1", "STAG2", "T1", "T10", "T101", "T102", "T2", "T3",
	"T4", "T7", "T71", "T72", "T73", "T8", "T80", "T81", "T82", "T9",
	"T91", "T92", "TEST10G", "THUMPER", "TRC28", "TRIUMF", "TSH1", "TST", "TST0", "TST1",
	"TST2", "TST3", "TST4", "TST5", "TST6", "TST7", "TST8", "TST9", "TYCP", "UNIX101",
	"UNIX1011", "UNIX1012", "UNIX1013", "UNIX1014", "UNIX102", "UNIX1021", "UNIX817", "UNIX8171", "UNIX8172", "UNIX8173",
	"UNIX8174", "UNIX901", "UNIX902", "UNIX9021", "UNIX9022", "UNIX9023", "UNIX9024", "UNIX9025", "UNIX9026", "UNIX9027",
	"VENOM", "VENU", "VISTA", "W101", "W1011", "W1012", "W1013", "W1014", "W102", "W1021",
	"W817", "W8171", "W8172", "W8173", "W8174", "W901", "W902", "W9021", "W9022", "W9023",
	"W9024", "W9025", "W9026", "W9027", "WG73", "WIN101", "WIN1011", "WIN1012", "WIN1013", "WIN1014",
	"WIN102", "WIN1021", "WIN817", "WIN8171", "WIN8172", "WIN8173", "WIN8174", "WIN901", "WIN902", "WIN9021",
	"WIN9022", "WIN9023", "WIN9024", "WIN9025", "WIN9026", "WIN9027", "WINDOWS101", "WINDOWS1011", "WINDOWS1012", "WINDOWS1013",
	"WINDOWS1014", "WINDOWS102", "WINDOWS1021", "WINDOWS817", "WINDOWS8171", "WINDOWS8172", "WINDOWS8173", "WINDOWS8174", "WINDOWS901", "WINDOWS902",
	"WINDOWS9021", "WINDOWS9022", "WINDOWS9023", "WINDOWS9024", "WINDOWS9025", "WINDOWS9026", "WINDOWS9027", "XEXDB", "XE_XPT", "HSAGENT",
}

func Check(Host, Username, Password string, Port int, SID string) (bool, error) {
	var db *sql.DB
	var err error
	dataSourceName := fmt.Sprintf("oracle://%s:%s@%s:%d/%s", Username, Password, Host, Port, SID)
	db, err = sql.Open("oracle", dataSourceName)
	if err != nil {
		return false, err
	}
	defer db.Close()
	db.SetConnMaxLifetime(5 * time.Second)
	db.SetMaxIdleConns(0)
	err = db.Ping()
	if err != nil {
		if strings.Contains(err.Error(), "ORA-28009") {
			return true, nil
		}
		return false, err
	}
	return true, nil
}

func GetSID(Host string, Port int, sids []string) string {
	for _, sid := range sids {
		if CheckSID(sid, Host, Port) {
			return sid
		}
	}
	return ""
}

func CheckSID(sid, Host string, Port int) bool {
	dataSourceName := fmt.Sprintf("oracle://sid:sid@%s:%d/%s", Host, Port, sid)
	db, err := sql.Open("oracle", dataSourceName)
	if err != nil {
		return false
	}
	db.SetConnMaxLifetime(3 * time.Second)
	db.SetMaxIdleConns(0)
	defer func() {
		if e := recover(); e != nil {
			err = errors.New(fmt.Sprint("sid check failed: ", Host, e))
			slog.Println(slog.DEBUG, err, e)
		}
	}()

	err = db.Ping()
	if err == nil {
		db.Close()
		return true
	}
	if strings.Contains(err.Error(), "ORA-") == false {
		return false
	}
	if strings.Contains(err.Error(), "ORA-12505") {
		return false
	}
	if strings.Contains(err.Error(), "ORA-12504") {
		return false
	}
	if strings.Contains(err.Error(), "ORA-12514") {
		return false
	}
	return true
}

func CheckProtocol(Host string, Port int) bool {
	dataSourceName := fmt.Sprintf("oracle://sid:sid@%s:%d/orcl", Host, Port)
	db, err := sql.Open("oracle", dataSourceName)
	if err != nil {
		return false
	}
	db.SetConnMaxLifetime(3 * time.Second)
	db.SetMaxIdleConns(0)
	err = db.Ping()
	if err == nil {
		db.Close()
		return true
	}
	return strings.Contains(err.Error(), "ORA-")
}
