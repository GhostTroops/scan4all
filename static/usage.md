# 参数

```sh
scan4all -h
```

运行 -h 参数即可查看所有参数的描述信息

```yaml
Usage:
  ./scan4all [flags]

INPUT:
   -host string[]              hosts to scan Ports for (comma-separated)
   -list, -l string            list of hosts to scan Ports (file)
   -exclude-hosts, -eh string  hosts to exclude from the scan (comma-separated)
   -exclude-file, -ef string   list of hosts to exclude from scan (file)

PORT:
   -port, -p string            Ports to scan (80,443, 100-200
   -top-Ports, -tp string      top Ports to scan (default http)
   -exclude-Ports, -ep string  Ports to exclude from scan (comma-separated)
   -Ports-file, -pf string     list of Ports to exclude from scan (file)
   -exclude-cdn, -ec           skip full port scans for CDN's (only checks for 80,443)

RATE-LIMIT:
   -c int     general nclruner worker threads (default 25)
   -rate int  packets to send per second (default 1000)

OUTPUT:
   -o, -output string  file to write output to (optional)
   -json               write output in JSON lines format
   -csv                write output in csv format

CONFIGURATION:
   -ceyeapi               ceye.io api key
   -ceyedomain            ceye.io subdomain  
   -np                    Skip POC check
   -scan-all-ips, -sa     scan all the IP's associated with DNS record
   -scan-type, -s string  type of port scan (SYN/CONNECT) (default "s")
   -source-ip string      source ip
   -interface-list, -il   list available interfaces and public ip
   -interface, -i string  network Interface to use for port scan
   -nmap                  invoke nmap scan on Targets (nmap must be installed) - Deprecated
   -nmap-cli string       nmap command to run on found results (example: -nmap-cli 'nmap -sV')
   -r string              list of custom resolver dns resolution (comma separated or from file)
   -proxy string          socks5 proxy
   -resume                resume scan using resume.cfg
   -stream                stream mode (disables resume, nmap, verify, retries, shuffling, etc)

OPTIMIZATION:
   -retries int       number of retries for the port scan (default 3)
   -timeout int       millisecond to wait before timing out (default 1000)
   -warm-up-time int  time in seconds between scan phases (default 2)
   -ping              ping probes for verification of host
   -verify            validate the Ports again with TCP verification

DEBUG:
   -debug                    display debugging information
   -verbose, -v              display verbose output
   -no-color, -nc            disable colors in CLI output
   -silent                   display only results in output
   -version                  display version of naabu
   -stats                    display stats of the running scan
   -si, -stats-interval int  number of seconds to wait between showing a statistics update (default 5)
```