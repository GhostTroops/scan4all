package rceverify

import _ "embed"

// Java source files (for reference and recompilation)
//
//go:embed java/ExecTemplateJDK8.java
var ExecTemplateJDK8Java string

//go:embed java/CmdServlet.java
var CmdServletJava string

//go:embed java/CmdFilter.java
var CmdFilterJava string
