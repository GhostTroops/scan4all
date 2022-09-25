nmap.exe -F --top-Ports=65535 -n --unique --resolve-all -Pn -sU -sS --min-hostgroup 64 --max-retries 0 --host-timeout 10m --script-timeout 3m --version-intensity 9 --min-rate 5000 -T4  -iL %1 -oX %2
