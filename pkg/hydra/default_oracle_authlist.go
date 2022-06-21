package hydra

func DefaultOracleList() *AuthList {
	a := NewAuthList()
	a.Username = []string{
		"sys",
		"system",
		"admin",
		"test",
		"web",
		"orcl",
	}
	a.Password = []string{
		"123456",
		"abc123",
		"okmnji",
	}
	a.Special = []Auth{
		NewSpecialAuth("internal", "oracle"),
		NewSpecialAuth("system", "manager"),
		NewSpecialAuth("system", "oracle"),
		NewSpecialAuth("sys", "change_on_install"),
		NewSpecialAuth("SYS", "CHANGE_ON_INSTALLorINTERNAL"),
		NewSpecialAuth("SYSTEM", "MANAGER"),
		NewSpecialAuth("OUTLN", "OUTLN"),
		NewSpecialAuth("SCOTT", "TIGER"),
		NewSpecialAuth("ADAMS", "WOOD"),
		NewSpecialAuth("JONES", "STEEL"),
		NewSpecialAuth("CLARK", "CLOTH"),
		NewSpecialAuth("BLAKE", "PAPER."),
		NewSpecialAuth("HR", "HR"),
		NewSpecialAuth("OE", "OE"),
		NewSpecialAuth("SH", "SH"),
		NewSpecialAuth("DBSNMP", "DBSNMP"),
		NewSpecialAuth("sysman", "oem_temp"),
		NewSpecialAuth("aqadm", "aqadm"),
		NewSpecialAuth("ANONYMOUS", "ANONYMOUS"),
		NewSpecialAuth("CTXSYS", "CTXSYS"),
		NewSpecialAuth("DIP", "DIP"),
		NewSpecialAuth("DMSYS", "DMSYS"),
		NewSpecialAuth("EXFSYS", "EXFSYS"),
		NewSpecialAuth("MDDATA", "MDDATA"),
		NewSpecialAuth("MDSYS", "MDSYS"),
		NewSpecialAuth("MGMT_VIEW", "MGMT_VIEW"),
		NewSpecialAuth("OLAPSYS", "MANAGER"),
		NewSpecialAuth("ORDPLUGINS", "ORDPLUGINS"),
		NewSpecialAuth("ORDSYS", "ORDSYS"),
		NewSpecialAuth("WK_TEST", "WK_TEXT"),
	}
	return a
}
