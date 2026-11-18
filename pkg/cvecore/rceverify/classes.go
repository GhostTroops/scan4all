package rceverify

import _ "embed"

// Base64-encoded compiled Java class files (JDK 8, compiled with servlet-api.jar)
// These are decoded at runtime and served over HTTP for JNDI URLClassLoader loading.
// Version: v2 (Tomcat + WebLogic compatible filter registration)

//go:embed class_etj8.b64
var etj8B64 string

//go:embed class_etj8_1.b64
var etj81B64 string

//go:embed class_cmd.b64
var cmdB64 string

//go:embed class_filter.b64
var filterB64 string
