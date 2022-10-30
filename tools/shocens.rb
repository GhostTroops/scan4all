#!/usr/bin/env ruby
#
# Author: noah @thesubtlety
#
# Usage: shocens.rb [options]
#     -s, --shodan-search=SEARCH_TERM  Search Shodan by search term
#     -f, --shodan-by-file=FILE        Search terms separated by newline
#     -t, --shodan-filter=FILTER       Restrict Shodan search to standard filters
#                                         Examples: -t org -s 'org name' queries 'org:"org name"'
#                                         or -t net -s "192.168.1.0/24" queries "net:192.168.1.0/24"
#     -q, --censys-search=SEARCH_TERM  Your censys.io query. Examples: '127.0.0.1' or 'domain.tld'
#                                         or 'parsed.extensions=="domain.tld"'
#                                         or 'autonomous_system.description:"target"'
#                                         See https://censys.io/overview#Examples
#     -F, --censys-by-file=FILE        Search Censys with list of search terms separated by newline
#     -o, --save-output                Write output to csv file, ip list file, diff file
#     -l, --limit=NUM                  Limit result set to NUM multiple of 100
#     -d, --diff-last                  Compare last scan results and update diff file
#     -h, --help                       Show this message

# Shodan
require 'shodan'
require 'optparse'
require 'time'
require 'ruby_dig' #no-op with ruby 2.3+

# Censys
require 'rest-client'
require 'json'
require 'base64'
require 'optparse'

time                  = Time.now.strftime("%Y%m%d%H%M")

VERBOSE_HOST_INFO_FILE = "verbose-output-#{time}.csv"
DIFF_FILE             = "new-results-#{time}.txt"
IP_LIST_FILE          = "ips-list-#{time}.txt"
CERT_SITE_FILE        = "certwebsites-output-#{time}.txt"
IPS_PORTS_LIST_FILE   = "ips-ports-list.txt"
CENSYS_CSV_HEADER     = "ip,ports,server,powered_by,title,link,uniq_cert_names_csv"
SHODAN_CSV_HEADER     = "ip,port,host,http_host,title,server,location,link,certs"

CENSYS_API_URL        = "https://www.censys.io/api/v1"
CENSYS_UID            = ENV["CENSYS_UID"]
CENSYS_SECRET         = ENV["CENSYS_SECRET"]
SHODAN_KEY            = ENV["SHODAN_KEY"]

# Globals are bad
$current_results_hash = {}
$verbose_host_info    = []
$cert_sites           = []
$ips                  = []
$token_bucket         = 0
$censys_search_bool   = FALSE
$shodan_search_bool   = FALSE


def init_shodan
    SHODAN_KEY || raise("[!] Missing SHODAN_KEY environment variable...")
    @api = Shodan::Shodan.new(SHODAN_KEY)
    $shodan_search_bool = TRUE
end

def init_censys
    CENSYS_UID || raise("[!] Missing CENSYS_UID environment variable...")
    CENSYS_SECRET || raise("[!] Missing CENSYS_SECRET environment variable...")
    $censys_search_bool = TRUE
end

def check_file_exists(filename)
    return TRUE if File.exist?(filename)
    puts "[!] #{filename} doesn't exist! Exiting..."
    exit 1
end

# Censys
# TODO make less naiive
# 120 request/minute (no slow needed for one page @101 results per query)
# if more than one page. naiively sleep for five minutes to fill up bucket again
def check_token_bucket
    if $token_bucket >= 115
      puts "[!] Sleeping for five to prevent lock out...\n"
      sleep 60*5
      $token_bucket = 0
    end
end

# Censys
def catch_query_error(e)
    puts "\n[-] Error: #{e}"
    puts e.backtrace.join("\n").to_s if !e.response
    case e.response.code
        when 429
          puts "\n[-] Error: #{e.response}"
          puts "[!] Sleeping for 5 minutes to recharge... Please hold...\n\n"
          sleep 60 * 5
        when 400
          puts "\n[-] Error: #{e.response}"
          puts "[-] Check your query parameters..."
          exit 1
        else
          puts "\n[-] Error: #{e.response}"
          puts "[!] Sleeping a minute... maybe the problem will go away...\n\n"
          sleep 60
    end
end

def write_to_file(output_file, data)
    File.open(output_file, "a") do |f|
        # fragile assuming only arrays are being passed in
        f.puts data.join("\n").to_s
    end
end

def add_to_hash(ip, port)
    if $current_results_hash[ip]
        $current_results_hash[ip] << port
    else
        $current_results_hash[ip] = [port]
    end
end

def diff_last_scan
    old_results_array = []
    if File.exist?(IPS_PORTS_LIST_FILE)
        File.foreach(IPS_PORTS_LIST_FILE) do |l|
            old_results_array << [l.strip]
        end
    else
        puts "\n[!] No previous hosts to compare to..."
    end

    current_results_array = []
    $current_results_hash.sort{ |k,v| k[1] <=> v[1] }.each do |k,v|
        current_results_array << ["#{k}, #{v.join(", ")}"]
    end

    diff = current_results_array - old_results_array
    if diff.empty?
        puts "\n[!] No new properties"
    else
        puts "\n[!] New properties in this scan"
        puts diff.join("\n")
        write_to_file(DIFF_FILE, diff)
        puts "[+] Saved #{DIFF_FILE}"
    end
end

def save_output
    uniq_websites = $cert_sites.flatten.uniq.reject(&:nil?).reject(&:empty?).sort_by(&:downcase)
    uniq_ips = $ips.uniq.sort

    # write websites and ips
    write_to_file(IP_LIST_FILE, uniq_ips); puts "\n[+] Saved #{IP_LIST_FILE}" if !uniq_ips.empty?
    write_to_file(CERT_SITE_FILE,uniq_websites);  puts "[+] Saved #{CERT_SITE_FILE}" if !uniq_websites.empty?

    # write CSV
    if !$verbose_host_info.empty?
        header = ""
        $shodan_search_bool ? header = SHODAN_CSV_HEADER : header = CENSYS_CSV_HEADER
        write_to_file(VERBOSE_HOST_INFO_FILE, [header])
        write_to_file(VERBOSE_HOST_INFO_FILE, $verbose_host_info)
        puts "[+] Saved #{VERBOSE_HOST_INFO_FILE}"
    end

  # write ip/ports hash for diff list
    if !$current_results_hash.empty?
        File.open(IPS_PORTS_LIST_FILE, 'w') do |f|
            $current_results_hash.sort{ |k,v| k[1] <=> v[1] }.each do |k,v|
                f.puts "#{k}, #{v.join(', ')}"
            end
            puts "[+] Saved #{IPS_PORTS_LIST_FILE}"
        end
    end
end

def parse_censys_results(results)
    results["results"].each do |e|
        ip = e["ip"]
        ports = e["protocols"].map { |e| e.split("/")[0] }

        $ips << ip
        add_to_hash(ip,ports)

        puts "\nHost:\t\t#{ip}: ports #{ports.join(', ')}"

        tries ||= 0
        check_token_bucket
        begin
            detailed_resp = RestClient.get "#{CENSYS_API_URL}/view/ipv4/#{ip}",
                            {:Authorization => "Basic #{Base64.strict_encode64("#{CENSYS_UID}:#{CENSYS_SECRET}")}"}
            $token_bucket += 1
        rescue StandardError => e
            catch_query_error(e)
            ((tries += 1)) < 3 ? retry : exit(1)
        end

        details = JSON.parse(detailed_resp)
        begin
            server = details.fetch("80", {}).fetch("http", {}).fetch("get", {}).fetch("headers", {}).fetch("server", "") 
            powered_by = details.fetch("80",{}).fetch("http",{}).fetch("get",{}).fetch("headers",{}).fetch("x_powered_by","")
            title = details.fetch("80",{}).fetch("http",{}).fetch("get",{}).fetch("title","").split("\n")[0] || ""
            other_names = []
            other_names << [details.fetch("443",{}).fetch("https",{}).fetch("tls",{}).fetch("certificate",{}).fetch("parsed",{}).fetch("subject_dn","").split("CN=")[1]]
            other_names << details.fetch("443",{}).fetch("https",{}).fetch("tls",{}).fetch("certificate",{}).fetch("parsed",{}).fetch("extensions",{}).fetch("subject_alt_name",{}).fetch("dns_names","")
            uniq_cert_names_csv = other_names.uniq.join("|")

            puts "Server:\t\t#{server}"
            puts "Powered By:\t#{powered_by}"
            puts "Title:\t\t#{title}"
            puts "Cert Names:\t#{other_names.uniq.join(", ")}"

            $cert_sites.concat(other_names.uniq)

            link = "https://censys.io/ipv4/#{ip}"
            host_info = "#{ip},#{ports.join("|")},#{server},#{powered_by},#{title},#{link},#{uniq_cert_names_csv}"
            $verbose_host_info << host_info
        rescue StandardError => e
            puts "\n[-] Error: #{e}"
            puts e.backtrace.join("\n").to_s
            next
        end
    end
end

def parse_shodan_results(res)
    res["matches"].each do |h|
        begin
            ip = h["ip_str"].to_s || "0"
            port = h["port"].to_s || "0"
            add_to_hash(ip,port)
            host = h.dig("hostnames").join(",") || ""
            http_host = h.dig("http","host") || ""
            title = h.dig("http","title") || ""
            server = h.dig("http","server") || ""
            location = h.dig("http","location") || ""
            subject_certs = h.dig("ssl","cert","subject","CN") || ""
            tmpextcerts = h.dig("ssl","cert","extensions", 0, "data") || ""
            # wow cert data is a mess
            extcerts = !tmpextcerts.empty? ? tmpextcerts.split(/\\x../).reject(&:empty?).drop(1).join(",") : ""
            subject_certs = subject_certs.gsub(/[ \\()$%\!"#'\r\n]/,"")
            extcerts  = extcerts.gsub(/[ \\()$%\!"#'\r\n]/,"")
            link = "https://www.shodan.io/host/#{ip}"

            puts "\n"
            puts "IP:\t\t" + ip.to_s + ", port " + port.to_s
            puts "Host:\t\t#{http_host}"
            puts "Hostname:\t#{host}"
            puts "Title:\t\t#{title.gsub(/[\t\r\n,]/,"")}"
            puts "Server:\t\t#{server}"
            puts "Location:\t#{location}"
            puts "Certs:\t\t#{subject_certs} #{extcerts}"
            puts "\n"

            host_info = "#{ip},#{port},#{host},#{http_host},#{title.gsub(/[\t\r\n,]/,"")},#{server},#{location},#{link},#{subject_certs.gsub!(",","|")} #{extcerts.gsub!(",","|")}"
            $verbose_host_info << host_info
            $ips << ip

            tmpwebsites = subject_certs.split(/[,|]/)
            $cert_sites << tmpwebsites if !tmpwebsites.empty?
            tmpwebsites2 = extcerts.split(/[,|]/)
            $cert_sites << tmpwebsites2  if !tmpwebsites2.empty?

        rescue StandardError => e
            puts "[-] Error: #{e}"
            puts e.backtrace.join("\n").to_s
            next
        end
    end
end

def censys_search(query, limit)
    query.each do |q|
        tries ||= 0
        begin
            pagenum = 1
            total_pages = 1
            until pagenum > total_pages
                check_token_bucket
                begin
                    res = RestClient.post "#{CENSYS_API_URL}/search/ipv4", ({:query => q, :page => pagenum}).to_json,
                                {:Authorization => "Basic #{Base64.strict_encode64(CENSYS_UID + ":" + CENSYS_SECRET)}"}
                    $token_bucket += 1
                rescue StandardError => e
                    catch_query_error(e)
                    ((tries += 1)) < 3 ? retry : exit(1)
                end
                results = JSON.parse(res)
                returned_query = results["metadata"]["query"] || ""
                total = results["metadata"]["count"] || 0

                puts "[+] #{total} results for #{returned_query}\n" if pagenum == 1
                puts "[+] Limiting results to #{(limit / 100.to_f).ceil } pages..." if !limit.nil? && limit <= total
                ( !limit.nil? && limit <= total ) ? total_pages = (limit / 100.to_f).ceil : total_pages = results["metadata"]["pages"] || 0

                if total_pages > 1
                    puts "[!] This could take over #{(total_pages + (((total_pages*100) / 115) * 5))} minutes... Ctrl+C now if you do not wish to proceed... Sleeping for 5 seconds..."
                    sleep 5
                end
                puts "\n[+] Parsing page #{pagenum} of #{total_pages}\n"

                parse_censys_results(results)
                pagenum += 1
        end

        rescue SystemExit, Interrupt
            puts "\n[!] Ctrl+C caught. Exiting. Goodbye..."
        rescue StandardError => e
            puts "\n[-] Error: #{e}"
            puts e.backtrace.to_s
        end
    end
end

def search_shodan(query, limit)
    c = 0
    query.each do |q|
        begin
            c += 1
            sleep 10 if (c % 9).zero?
            pagenum = 1
            res = @api.search(q, page: pagenum)
            total = res['total']
            puts "[+] #{total} results in #{q}"

            puts "[+] Limiting results to #{ (limit / 100.to_f).ceil } pages..." if !limit.nil? && limit <= total
            ( !limit.nil? && limit <= total ) ? total_pages = ( limit / 100.to_f ).ceil : total_pages = ( total / 100.to_f ).ceil

            if total_pages > 1
                puts "[!] #{total_pages} pages of results- this could take a while... Ctrl+C now if you do not wish to proceed... Sleeping for 5 seconds..."
                sleep 5
                puts "\n[+] Parsing page #{pagenum} of #{total_pages}\n"
            end

            parse_shodan_results(res)

            d = 1
            until pagenum >= total_pages
                if d % 9 == 0 then sleep 10 end
                pagenum += 1
                puts "\n[+] Parsing page #{pagenum} of #{total_pages}\n"
                res = @api.search(q, page: pagenum)
                parse_shodan_results(res)
                d += 1
            end
        rescue SystemExit, Interrupt
            puts "\n[!] Ctrl+C caught. Exiting. Goodbye..."
        rescue StandardError => e
            puts "\n[-] Error: #{e}"
            puts e.backtrace.to_s
        end
    end
end

# TODO censys cert parsing
# pass use certificate instead of ipv4 query /search/certificates instead of /search/ipv4
# ({:query => "domain.com",:fields=>["parsed.subject_dn","parsed.issuer_dn","parsed.fingerprint_sha256"]})
# RestClient.get "#{CENSYS_API_URL}/view/certificates/sha256hashhere",{:Authorization => "Basic #{Base64.strict_encode64(CENSYS_UID+":"+CENSYS_SECRET)}"}
# r['results'].first['parsed.subject_dn'][0].split("CN=")[1]
# c['parsed']['names']
# c['parsed']['subject_dn']

def main
    start = Time.now

    help = ""
    options = {}
    OptionParser.new do |opt|
    opt.banner = "Usage: shocens.rb [options]"
        opt.on("-s", "--shodan-search=SEARCH_TERM", "Search Shodan by search term") { |o| options[:shodan_query] = o }
        opt.on("-f", "--shodan-by-file=FILE", "Search terms separated by newline") { |o| options[:shodan_search_file] = o }
        opt.on("-t", "--shodan-filter=FILTER", 'Restrict Shodan search to standard filters
                                        Examples: -t org -s \'org name\' queries \'org:"org name"\'
                                        or -t net -s "192.168.1.0/24" queries "net:192.168.1.0/24"'
                                        ) { |o| options[:shodan_filter] = o }

        opt.on("-q", "--censys-search=SEARCH_TERM", 'Your censys.io query. Examples: \'127.0.0.1\' or \'domain.tld\'
                                        or \'parsed.extensions=="domain.tld"\'
                                        or \'autonomous_system.description:"target"\'
                                        See https://censys.io/overview#Examples'
                                        ) { |q| options[:censys_query] = q }
        opt.on("-F", "--censys-by-file=FILE", "Search Censys with list of search terms separated by newline") { |o| options[:censys_search_file] = o }

        opt.on("-o", "--save-output", "Write output to csv file, ip list file, diff file") { options[:save_output] = TRUE}
        opt.on("-l", "--limit=NUM", Integer, "Limit result set to NUM multiple of 100") { |o| options[:limit] = o }
        opt.on("-d", "--diff-last", "Compare last scan results and update diff file") { options[:diff_last_scan] = TRUE}

        opt.on_tail("-h", "--help", "Show this message") { puts opt; exit }
        help = opt
    end.parse!

    unless options[:shodan_query] || options[:shodan_search_file] || options[:censys_search_file] || options[:censys_query]
        puts help
        exit 1
    end
    unless (options[:shodan_query] || options[:shodan_search_file]).nil? || (options[:censys_search_file] || options[:censys_query]).nil?
        puts "\n[-] Can't search both Shodan and Censys at the same time, sorry...\n\n"
        puts help
        exit 1
    end
    if (options[:shodan_query] && options[:shodan_search_file]) || (options[:censys_search_file] && options[:censys_query])
        puts "\n[-] Please choose a single search method...\n\n"
        puts help
        exit 1
    end

    query = []
    case
        when options[:shodan_query]
            init_shodan
            puts "[+] Beginning Shodan search for #{options[:shodan_filter]+":" if !options[:shodan_filter].nil?}#{options[:shodan_query]}"
            query << "#{ options[:shodan_filter] + ":" if !options[:shodan_filter].nil? }#{ "\"" + options[:shodan_query] + "\"" }"
            search_shodan(query, options[:limit])

        when options[:shodan_search_file]
            init_shodan
            check_file_exists(options[:shodan_search_file])
            puts "\n[+] Beginning Shodan search #{"with filter '#{options[:shodan_filter]}' " unless options[:shodan_filter].nil?}with file '#{options[:shodan_search_file]}' ..."
            File.foreach(options[:shodan_search_file]) do |l|
                shodan_query = l.strip
                next if shodan_query.to_s.eql?('')
                query << "#{ options[:shodan_filter] + ":" unless options[:shodan_filter].nil? }\"#{shodan_query}\""
            end
            search_shodan(query, options[:limit])

        when options[:censys_query]
            init_censys
            query << "#{options[:censys_query]}"
            puts "[+] Beginning Censys search for #{options[:censys_query]}"
            censys_search(query, options[:limit])

        when options[:censys_search_file]
            init_censys
            check_file_exists(options[:censys_search_file])
            File.foreach(options[:censys_search_file]) do |l|
                next if l.strip.empty?
                query << l.strip
            end
            puts "[+] Beginning Censys search with #{options[:censys_search_file]}..."
            censys_search(query, options[:limit])

        else
            puts "[!] Error parsing query. Check your options..."
            puts help
        end

    diff_last_scan if options[:diff_last_scan]
    save_output if options[:save_output]

    puts "\n[+] Found #{$ips.uniq.count} hosts..."
    puts "[+] Found #{$cert_sites.uniq.count} websites in certificates..."

    finish = Time.now
    delta = finish - start
    puts "\n[+] Completed in about #{delta.to_i / 60} minutes"
end

main
