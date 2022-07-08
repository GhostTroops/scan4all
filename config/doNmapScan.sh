#!/bin/bash
XRate=5000
function doMasScan {
    if [[ -f $1 ]] ; then
        echo $PPSSWWDD|sudo -S nmap -F --top-ports=65535 -n --unique --resolve-all -Pn -sS --min-hostgroup 64 --max-retries 0 --host-timeout 10m --script-timeout 3m --version-intensity 9 --min-rate ${XRate} -T4  -iL $1 -oX $2
    else
        echo $PPSSWWDD|sudo -S nmap -F --top-ports=65535 -n --unique --resolve-all -Pn -sS --min-hostgroup 64 --max-retries 0 --host-timeout 10m --script-timeout 3m --version-intensity 9 --min-rate ${XRate} -T4  $1 -oX $2
    fi
}
doMasScan $1 $2
