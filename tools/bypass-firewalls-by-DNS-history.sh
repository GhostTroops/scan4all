#!/usr/bin/env bash
################################################################################
######################## Constants and variables ###############################
################################################################################
SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
# Colors
GREEN='\033[1;32m'
NC='\033[0m' # No Color
RED='\033[1;31m'
YELLOW='\033[0;33m'
# Input variables
checkall=0
POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"
case $key in
    -d|--domain)
    domain="$2"
    shift # past argument
    shift # past value
    ;;
    -o|--outputfile)
    outfile="$2"
    shift # past argument
    shift # past value
    ;;
    -l|--listsubdomains)
    listsubdomains="$2"
    shift # past argument
    shift # past value
    ;;
    -a|--checkall)
    checkall=1
    shift # past argument
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

################################################################################
######################## Show Script Information ###############################
################################################################################
if [ -z "$domain" ] ; then
	  echo 'usage: ./bypass-firewalls-by-DNS-history.sh -d example.com'
    echo '-d --domain: domain to bypass'
    echo "-o --outputfile: output file with IP's only"
    echo '-l --listsubdomains: list with subdomains for extra coverage'
    echo '-a --checkall: Check all subdomains for a WAF bypass'
    exit 0
fi
################################################################################
######################## Various ###############################################
################################################################################

# Check if jq is installed
jq --help >/dev/null 2>&1 || { echo >&2 "'jq' is needed for extra subdomain lookups, but it's not installed. Consider installing it for better results (eg.: 'apt install jq'). Aborting."; exit 1; }

# Cleanup temp files when program was interrupted.
rm /tmp/waf-bypass-*$domain* &> /dev/null

# Add extra Subdomains
if [ -n "$listsubdomains" ] ; then
  cat $listsubdomains > /tmp/waf-bypass-alldomains-$domain.txt
fi

################################################################################
######################## Show Logo  ############################################
################################################################################

cat << "EOF"
-------------------------------------------------------------
 __          __     ______   _
 \ \        / /\   |  ____| | |
  \ \  /\  / /  \  | |__    | |__  _   _ _ __   __ _ ___ ___
   \ \/  \/ / /\ \ |  __|   | '_ \| | | | '_ \ / _` / __/ __|
    \  /\  / ____ \| |      | |_) | |_| | |_) | (_| \__ \__ \
     \/  \/_/    \_\_|      |_.__/ \__, | .__/ \__,_|___/___/
                                    __/ | |
                                   |___/|_|
Via DNS history. ( @vincentcox_be | vincentcox.com )
-------------------------------------------------------------
EOF

################################################################################
######################## Matchmaking function ##################################
################################################################################
# Purpose: Sometimes old IP's become different people's server. For example a
# company uses a Digitalocean VPS and after one year they switched to amazon
# so they remove their VPS instance. The IP is then released and then used by
# some dude's server for a hobby project. To verify if we got a hit, we need
# to inspect the HTML and compare it from the WAF and the direct IP and Calculate
# a match percentage. This is exactly what we are going to do here.
# This script is called later on in the script.

## Most sites redirect HTTP to HTTPS, so the response body of http will be empty, causing false positives to appear.
{
if (curl --silent -v http://$domain 2>&1|tr '\n' ' '| grep -e "Moved Permanently.*https://$domain"); then
  cp "/tmp/waf-bypass-https-$domain" "/tmp/waf-bypass-http-$domain"
fi
} &> /dev/null # hide verbose output curl, somehow --silent is not enough when verbose is on.

## This function is called to do the actual comparing
function matchmaking {
file1=$1
file2=$2
ip=$3
matchmaking=$4
domain=$5
protocol=$6
## Get the original content of the website to compare this to during the matchmaking
curl --silent -o "/tmp/waf-bypass-https-$domain" "https://$domain"
curl --silent -o "/tmp/waf-bypass-http-$domain" "http://$domain"
touch $file1
touch $file2
thread=$!
sizefile1=$(cat $file1 | wc -l )
sizefile2=$(cat $file2 | wc -l )
biggestsize=$(( $sizefile1 > $sizefile2 ? $sizefile1 : $sizefile2 ))
if [[ $biggestsize -ne 0  ]]; then
  difference=$(( $(sdiff -B -b -s $file1 $file2 | wc -l) ))
  confidence_percentage=$(( 100 * (( $biggestsize - ${difference#-} )) / $biggestsize ))
  if [[ $confidence_percentage -gt 0 ]]; then
    echo "$ip" >> "$outfile"
    if [[ $checkall -le 0 ]];then
      echo -e "$protocol://$ip | $confidence_percentage % | $(curl --silent https://ipinfo.io/$ip/org )" >>  /tmp/waf-bypass-output-$domain.txt
    else
      echo -e "$protocol://$domain | $ip | $confidence_percentage % | $(curl --silent https://ipinfo.io/$ip/org )" >>  /tmp/waf-bypass-output-$domain.txt
    fi
  fi

  # ---- Debugging Info ----
  echo "$file1 $file2" >> /tmp/waf-bypass-thread-$thread.txt
  echo "#Lines $file1: $sizefile1" >> /tmp/waf-bypass-thread-$thread.txt
  echo "#Lines $file2: $sizefile2" >> /tmp/waf-bypass-thread-$thread.txt
  echo "Different lines: $difference" >> /tmp/waf-bypass-thread-$thread.txt
  echo -e "$ip | $confidence_percentage %" >> /tmp/waf-bypass-thread-$thread.txt
  echo "----" >> /tmp/waf-bypass-thread-$thread.txt
  # if [ "$confidence_percentage" -gt 0 ]; then
  # cat /tmp/waf-bypass-thread-$thread.txt
  # fi

  # Uncomment the following line to output the debugging info.
  # cat /tmp/waf-bypass-thread-$thread.txt
  # ++++ Debugging Info ++++
  rm /tmp/waf-bypass-thread-$thread.txt
fi
}

################################################################################
######################## IP Validation #########################################
################################################################################
# Purpose: we need to check if the IP we find is not just the current IP and not
# a public WAF service.
# If no output file is specified
if [ -z "$outfile" ]; then
  outfile=/tmp/waf-bypass-$domain-log.txt # Get's removed anyway at the end of script.
fi
if [ -f "$outfile" ]; then
  rm "$outfile"
fi

# Exclude Public Known WAF IP's
PUBLICWAFS='103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 104.16.0.0/12 108.162.192.0/18 131.0.72.0/22 141.101.64.0/18 162.158.0.0/15 172.64.0.0/13 173.245.48.0/20 188.114.96.0/20 190.93.240.0/20 197.234.240.0/22 198.41.128.0/17 199.83.128.0/21 198.143.32.0/19 149.126.72.0/21 103.28.248.0/22 45.64.64.0/22 185.11.124.0/22 192.230.64.0/18 107.154.0.0/16 45.60.0.0/16 45.223.0.0/16'
function in_subnet {
    # Determine whether IP address is in the specified subnet.
    #
    # Args:
    #   sub: Subnet, in CIDR notation.
    #   ip: IP address to check.
    #
    # Returns:
    #   1|0
    #
    local ip ip_a mask netmask sub sub_ip rval start end

    # Define bitmask.
    local readonly BITMASK=0xFFFFFFFF

    # Read arguments.
    IFS=/ read sub mask <<< "${1}"
    IFS=. read -a sub_ip <<< "${sub}"
    IFS=. read -a ip_a <<< "${2}"

    # Calculate netmask.
    netmask=$(($BITMASK<<$((32-$mask)) & $BITMASK))

    # Determine address range.
    start=0
    for o in "${sub_ip[@]}"
    do
        start=$(($start<<8 | $o))
    done

    start=$(($start & $netmask))
    end=$(($start | ~$netmask & $BITMASK))

    # Convert IP address to 32-bit number.
    ip=0
    for o in "${ip_a[@]}"
    do
        ip=$(($ip<<8 | $o))
    done

    # Determine if IP in range.
    (( $ip >= $start )) && (( $ip <= $end )) && rval=1 || rval=0
    echo "${rval}"
}

function ip_is_waf {
IP=$1
for subnet in $PUBLICWAFS
do
    (( $(in_subnet $subnet $IP) )) &&
        echo 1 && break
done
}

################################################################################
################### Get Top Domain when sub is given  ##########################
################################################################################
function get_top_domain {
  domain=$1
  top_domain=$(curl -s "http://tldextract.appspot.com/api/extract?url=$domain" | jq ' .domain, .tld' | tr -d '"' |tr '\r\n' '.' | rev | cut -c2- | rev)
  if [ "$domain" != "$top_domain" ]; then
      echo $top_domain
  fi
}

################################################################################
######################## Subdomain Gathering  ##################################
################################################################################
# Purpose: Subdomains can point to origin IP's behind the firewall (WAF).

# Function to get subdomains from DNSDumpster
function dnsdumpster_subdomains {
domain=$1
curl https://dnsdumpster.com -o /dev/null -c /tmp/dnsdumpster-$domain-cookies.txt -s
CSRF="$(grep csrftoken /tmp/dnsdumpster-$domain-cookies.txt | cut -f 7)"
curl -s -X 'POST' -H 'Host: dnsdumpster.com' -H 'Pragma: no-cache' -H 'Cache-Control: no-cache' -H 'Upgrade-Insecure-Requests: 1' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36' -H 'Origin: https://dnsdumpster.com' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8' -H 'Referer: https://dnsdumpster.com/' -H 'Accept-Language: en-US,en;q=0.9,nl;q=0.8' -H "Cookie: csrftoken=$CSRF" -b "csrftoken=$CSRF" --data-binary "csrfmiddlewaretoken=$CSRF&targetip=$domain" -o /tmp/dnsdumpster-$domain-output.txt 'https://dnsdumpster.com/'
regex='\w*\.'$domain
cat /tmp/dnsdumpster-$domain-output.txt | grep -oh "$regex" | sort -u
rm /tmp/dnsdumpster-$domain-output.txt
rm /tmp/dnsdumpster-$domain-cookies.txt
}

# DNSDumpster (call function)
echo "$(dnsdumpster_subdomains $domain)" >> /tmp/waf-bypass-alldomains-$domain.txt
# Certspotter
curl -s https://certspotter.com/api/v0/certs?domain=$domain | jq -c '.[].dns_names' | grep -o '"[^"]\+"' | grep "$domain" | sed 's/"//g' >> /tmp/waf-bypass-alldomains-$domain.txt
# Virustotal
curl -H 'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36' -s https://www.virustotal.com/ui/domains/$domain/subdomains\?limit\= | jq '.data[].id' | grep -o '"[^"]\+"' | grep "$domain" | sed 's/"//g' >> /tmp/waf-bypass-alldomains-$domain.txt
# Add own domain
echo "$domain" >> /tmp/waf-bypass-alldomains-$domain.txt
# Add main (top level) domain if subdomain is inputted domain
echo "$(get_top_domain $domain)" >> /tmp/waf-bypass-alldomains-$domain.txt
# Filter unique ones + remove wildcards
cat  /tmp/waf-bypass-alldomains-$domain.txt | sort -u | grep -v -E '\*' >  /tmp/waf-bypass-domains-filtered-$domain.txt
# Read file to array. Readarray doesn't work on OS X, so we use the traditional way.
while IFS=\= read var; do
    domainlist+=($var)
done < /tmp/waf-bypass-domains-filtered-$domain.txt

# ---- Debugging Info ----
# echo "Using the IP's of the following (sub)domains for max coverage:"
# echo $(echo ${domainlist[*]})
# ++++ Debugging Info ++++

echo -e "${YELLOW}[-] $(echo ${#domainlist[@]}) Domains collected...${NC}"

################################################################################
######################## Get IP's from subdomains  #############################
################################################################################

progresscounter=0
for domainitem in "${domainlist[@]}"
do
   progresscounter=$(($progresscounter+1))
   echo -ne "${YELLOW}[-] Scraping IP's from (sub)domains ($((100*$progresscounter/${#domainlist[@]}))%)${NC}\r"
   domainitem=$( echo $domainitem | tr -d '\n')
   ### Source: viewdns.info
   list_ips=$list_ips" "$( curl --max-time 10 -s -H 'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36' -H 'content-type: application/json;charset=UTF-8' -H 'accept: application/json, text/plain, */*' https://viewdns.info/iphistory/?domain=$domainitem | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort -u)
   ### Source: SecurityTrials
   list_ips=$list_ips" "$( curl --max-time 10 -s "https://securitytrails.com/domain/$domainitem/history/a" | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' )
   ### Source: Security Trials API (alternative)
   list_ips=$list_ips" "$(curl -s "https://securitytrails.com/app/api/v1/history/$domainitem/dns/a?page=0" -H 'pragma: no-cache' -H 'origin: https://securitytrails.com' -H 'accept-encoding: gzip, deflate, br' -H 'accept-language: en-US,en;q=0.9,nl;q=0.8' -H 'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36' -H 'content-type: application/json;charset=UTF-8' -H 'accept: application/json, text/plain, */*' -H 'cache-control: no-cache' -H 'authority: securitytrails.com' -H "referer: https://securitytrails.com/domain/$domainitem/history/a" --data-binary '{"captcha":null,"_csrf_token":""}' --compressed | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
   ### Source: http://crimeflare.com/
   list_ips=$list_ips" "$( curl --max-time 15 -s 'http://www.crimeflare.com:82/cgi-bin/cfsearch.cgi' -H 'Connection: keep-alive' -H 'Pragma: no-cache' -H 'Cache-Control: no-cache' -H 'Origin: http://www.crimeflare.com:82' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 'Content-Type: application/x-www-form-urlencoded' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.67 Safari/537.36' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8' -H 'Referer: http://www.crimeflare.com:82/cfs.html' -H 'Accept-Encoding: gzip, deflate' -H 'Accept-Language: en-US,en;q=0.9,nl;q=0.8' --data "cfS=$domainitem" --compressed  | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' )
done
echo "" # Fix new line issue
list_ips=$(echo $list_ips | tr " " "\n" | sort -u )
echo -e "${YELLOW}[-] $( echo $list_ips | tr " " "\n" | wc -l | tr -d '[:space:]') IP's gathered from DNS history...${NC}"
# ---- Debugging Info ----
# echo -e "${YELLOW}[!] IP's: $(echo ${list_ips[*]}) ${NC}"
# ++++ Debugging Info ++++
################################################################################
######################## Bypass Test ###########################################
################################################################################
# For each IP test the bypass and calculate the match %
echo -e "${YELLOW}[-] Launching requests to origin servers...${NC}"
if [[ $checkall -eq 0 ]];then
  for ip in $list_ips;do
    if [[ $(ip_is_waf $ip) -eq 0 ]];then
      # Remove current IP's via nslookup
      currentips=$(nslookup $domain | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
      protocol="https"
      (if (curl --fail --max-time 10 --silent -k "$protocol://$domain" --resolve "$domain:443:$ip" | grep "html" | grep -q -v "was rejected" );then if [[ $currentips != *"$ip"* ]];then curl --silent -o "/tmp/waf-bypass-$protocol-$ip-$domain" -k -H "Host: $domain" "$protocol"://"$ip"/ ; matchmaking "/tmp/waf-bypass-$protocol-$domain" "/tmp/waf-bypass-$protocol-$ip-$domain" "$ip" "$checkall" "$domain" "$protocol";wait; fi; fi) & pid=$!;
      PID_LIST+=" $pid";
      protocol="http"
      (if (curl --fail --max-time 10 --silent -k "$protocol://$domain" --resolve "$domain:80:$ip" | grep "html" | grep -q -v "was rejected" );then if [[ $currentips != *"$ip"* ]];then curl --silent -o "/tmp/waf-bypass-$protocol-$ip-$domain" -k -H "Host: $domain" "$protocol"://"$ip"/ ; matchmaking "/tmp/waf-bypass-$protocol-$domain" "/tmp/waf-bypass-$protocol-$ip-$domain" "$ip" "$checkall" "$domain" "$protocol";wait; fi; fi) & pid=$!;
      PID_LIST+=" $pid";
    fi
  done
else
for domainitem in "${domainlist[@]}";do
  tempstorage=$domain
  domain=$domainitem
  for ip in $list_ips;do
    if [[ $(ip_is_waf $ip) -eq 0 ]];then
      # Remove current IP's via nslookup
      currentips=$(nslookup $domain | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
      protocol="https"
      (if (curl --fail --max-time 10 --silent -k "$protocol://$domain" --resolve "$domain:443:$ip" | grep "html" | grep -q -v "was rejected" );then if [[ $currentips != *"$ip"* ]];then curl --silent -o "/tmp/waf-bypass-$protocol-$ip-$domain" -k -H "Host: $domain" "$protocol"://"$ip"/ ; matchmaking "/tmp/waf-bypass-$protocol-$domain" "/tmp/waf-bypass-$protocol-$ip-$domain" "$ip" "$checkall" "$domain" "$protocol";wait; fi; fi) & pid=$!;
      PID_LIST+=" $pid";
      protocol="http"
      (if (curl --fail --max-time 10 --silent -k "$protocol://$domain" --resolve "$domain:80:$ip" | grep "html" | grep -q -v "was rejected" );then if [[ $currentips != *"$ip"* ]];then curl --silent -o "/tmp/waf-bypass-$protocol-$ip-$domain" -k -H "Host: $domain" "$protocol"://"$ip"/ ; matchmaking "/tmp/waf-bypass-$protocol-$domain" "/tmp/waf-bypass-$protocol-$ip-$domain" "$ip" "$checkall" "$domain" "$protocol";wait; fi; fi) & pid=$!;
      PID_LIST+=" $pid";
    fi
  done
  domain=$tempstorage
done
fi
echo -e "${YELLOW}[-] Waiting on replies from origin servers...${NC}"
trap "kill $PID_LIST" SIGINT
wait $PID_LIST
if [ ! -f "$outfile" ]; then
  echo -e "${RED}[-] No Bypass found!${NC}"
else
  echo -e "${GREEN}[+] Bypass found!${NC}"
	sort -u -o "$outfile-tmp" "$outfile"
  mv "$outfile-tmp" "$outfile"
  if [[ $checkall -eq 0 ]];then
    echo -e "[IP] | [Confidence] | [Organisation]" >>  /tmp/waf-bypass-output-$domain-2.txt
  else
    echo -e "[Domain] | [IP] | [Confidence] | [Organisation]" >>  /tmp/waf-bypass-output-$domain-2.txt
  fi
  cat /tmp/waf-bypass-output-$domain.txt | sort -ur >> /tmp/waf-bypass-output-$domain-2.txt
  cat /tmp/waf-bypass-output-$domain-2.txt > /tmp/waf-bypass-output-$domain.txt
fi

################################################################################
######################## Presenting output + cleanup ###########################
################################################################################

# When checkall is enabled, merge all results to main file
for domainitem in "${domainlist[@]}"
do
  if [ "$domainitem" != "$domain" ];then
    touch "/tmp/waf-bypass-output-$domainitem.txt"
    cat "/tmp/waf-bypass-output-$domainitem.txt" >> "/tmp/waf-bypass-output-$domain.txt"
  fi
done

touch /tmp/waf-bypass-output-$domain.txt # If no IP's were found, the script will be empty.
cat "/tmp/waf-bypass-output-$domain.txt" | column -s"|" -t

# Cleanup temp files
rm /tmp/waf-bypass-*$domain*
