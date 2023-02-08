package byps404

import (
	"bufio"
	b64 "encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Global vars
var maxThreads int = 1
var wg sync.WaitGroup
var queue int = 0
var verbose = false
var rateLimit = 5
var rateBoolean = true
var sem = make(chan int, maxThreads)
var lastPart, previousParts string

func DoCheckByPass404(szUrl string) {
	options := os.Args[1 : len(os.Args)-1]

	rateLimit = 128
	maxThreads = 8
	sem = make(chan int, maxThreads)
	rateBoolean = false
	verbose = true

	byp4xx(options, szUrl)
}

func curl_code_response(message string, options []string, url string) {
	// Append the options and the URL to the curl command
	codeOptions := []string{"-k", "-s", "-o", "/dev/null", "-w", "\"%{http_code}\""}
	payload := append(options, url)
	payload = append(codeOptions, payload...)
	curlCommand := exec.Command("curl", payload...)

	// Execute the command and get the output
	output, _ := curlCommand.CombinedOutput()
	outputStr := strings.ReplaceAll(string(output), "\"", "")
	code, _ := strconv.Atoi(outputStr)
	if code >= 200 && code < 300 {
		outputStr = "\033[32m" + outputStr + "\033[0m"
		fmt.Println(message, outputStr)
	} else if code >= 300 && code < 400 {
		outputStr = "\033[33m" + outputStr + "\033[0m"
		fmt.Println(message, outputStr)
	} else {
		if verbose {
			outputStr = "\033[31m" + outputStr + "\033[0m"
			fmt.Println(message, outputStr)
		}
	}
	if rateBoolean {
		rateLimit_mod := 1.0 / float64(rateLimit) * 1000.0
		time.Sleep(time.Duration(rateLimit_mod) * time.Millisecond)
	}
	defer wg.Done()
}

func byp4xx(options []string, url string) {
	//Parse the URL
	if strings.HasSuffix(url, "/") {
		parts := strings.Split(strings.TrimRight(url, "/"), "/")
		lastPart = parts[len(parts)-1]
		lastPart = lastPart + "/"
		previousParts = strings.Join(parts[:len(parts)-1], "/")
	} else {
		parts := strings.Split(url, "/")
		lastPart = parts[len(parts)-1]
		previousParts = strings.Join(parts[:len(parts)-1], "/")
	}

	//Run modules
	fmt.Println("\033[31m===== " + url + " =====\033[0m")
	verbTampering(options, url)
	headers(options, url)
	userAgent(options, url)
	extensions(options, url)
	defaultCreds(options, url)
	caseSensitive(options, url)
	midPaths(options, url)
	endPaths(options, url)
	bugBounty(options, url)
}

// verb测试
func verbTampering(options []string, url string) {
	fmt.Println("\033[32m==VERB TAMPERING==\033[0m")
	//VERB TAMPERING
	file, _ := os.Open("config/bps404/verbs.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		sem <- 1
		wg.Add(1)
		go func() {
			options_mod := append(options, "-X", line)
			curl_code_response(line+":", options_mod, url)
			<-sem
		}()
	}
	wg.Wait()
}

func headers(options []string, url string) {
	//HEADERS + IP
	fmt.Println("\033[32m==HEADERS==\033[0m")
	file, _ := os.Open("config/bps404/headers.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		file2, _ := os.Open("config/bps404/ip.txt")
		defer file2.Close()
		scanner2 := bufio.NewScanner(file2)
		for scanner2.Scan() {
			line := scanner.Text()
			line2 := scanner2.Text()
			sem <- 1
			wg.Add(1)
			go func() {
				line = line + line2
				options_mod := append(options, "-H", line)
				curl_code_response(line+":", options_mod, url)
				<-sem
			}()
		}
	}
	wg.Wait()
}

func userAgent(options []string, url string) {
	//USER AGENT
	fmt.Println("\033[32m==USER AGENTS==\033[0m")
	file, _ := os.Open("config/bps404/UserAgents.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		sem <- 1
		wg.Add(1)
		go func() {
			line = "User-Agent: " + line
			options_mod := append(options, "-H", line)
			curl_code_response(line+":", options_mod, url)
			<-sem
		}()
	}
	wg.Wait()
}

func extensions(options []string, url string) {
	//EXTENSIONS
	fmt.Println("\033[32m==EXTENSIONS==\033[0m")
	file, _ := os.Open("config/bps404/extensions.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		sem <- 1
		wg.Add(1)
		go func() {
			url_mod := url + line
			curl_code_response(line+":", options, url_mod)
			<-sem
		}()
	}
	wg.Wait()
}

func defaultCreds(options []string, url string) {
	//DEFAULT CREDS
	fmt.Println("\033[32m==DEFAULT CREDS==\033[0m")
	file, _ := os.Open("config/bps404/defaultcreds.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		sem <- 1
		wg.Add(1)
		go func() {
			creds := line
			sEnc := b64.StdEncoding.EncodeToString([]byte(line))
			line = "Authorization: Basic " + sEnc
			options_mod := append(options, "-H", line)
			curl_code_response(creds+":", options_mod, url)
			<-sem
		}()
	}
	wg.Wait()
}

func caseSensitive(options []string, url string) {
	//Case sensitive

	fmt.Println("\033[32m==CASE SENSITIVE==\033[0m")
	for i := range lastPart {
		modifiedUri := ""
		for j, r := range lastPart {
			if j == i {
				if r >= 'A' && r <= 'Z' {
					modifiedUri += string(r + ('a' - 'A'))
				} else if r >= 'a' && r <= 'z' {
					modifiedUri += string(r - ('a' - 'A'))
				}
			} else {
				modifiedUri += string(r)
			}
		}
		sem <- 1
		wg.Add(1)
		go func() {
			url_mod := previousParts + "/" + modifiedUri
			curl_code_response(modifiedUri+":", options, url_mod)
			<-sem
		}()
	}
	wg.Wait()
}

func midPaths(options []string, url string) {
	//MID PATHS
	fmt.Println("\033[32m==MID PATHS==\033[0m")
	file, _ := os.Open("config/bps404/midpaths.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		sem <- 1
		wg.Add(1)
		go func() {
			options_mod := append(options, "--path-as-is")
			url_mod := previousParts + "/" + line + "/" + lastPart
			curl_code_response(line+":", options_mod, url_mod)
			<-sem
		}()
	}
	wg.Wait()
}

func endPaths(options []string, url string) {
	//END PATHS
	fmt.Println("\033[32m==END PATHS==\033[0m")
	file, _ := os.Open("config/bps404/endpaths.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		sem <- 1
		wg.Add(1)
		go func() {
			options_mod := append(options, "--path-as-is")
			url_mod := previousParts + "/" + lastPart + line
			curl_code_response(line+":", options_mod, url_mod)
			<-sem
		}()
	}
	wg.Wait()
}

func bugBounty(options []string, url string) {

	//BUG BOUNTY
	fmt.Println("\033[32m==BUG BOUNTY TIPS==\033[0m")
	wg.Add(1)
	sem <- 1
	go func() {
		url_mod := previousParts + "/%2e/" + lastPart
		curl_code_response("/%2e/"+lastPart+":", options, url_mod)
		<-sem
	}()
	wg.Add(1)
	sem <- 1
	go func() {
		url_mod := previousParts + "/%ef%bc%8f" + lastPart
		options_mod := append(options, "--path-as-is")
		curl_code_response("/%ef%bc%8f"+lastPart+":", options_mod, url_mod)
		<-sem
	}()

	/*wg.Add(1)
	  	sem <- 1
	  	go func(){
	  		options_mod := append(options,"--path-as-is")
	  		url_mod := previousParts+"/%ef%bc%8f"+lastPart+"/."
	   	curl_code_response("/%ef%bc%8f"+lastPart+"/.:", options_mod, url_mod)
	   	<-sem
	  	}()*/
	wg.Add(1)
	sem <- 1
	go func() {
		url_mod := previousParts + "/" + lastPart + "?"
		curl_code_response("/"+lastPart+"?:", options, url_mod)
		<-sem
	}()
	wg.Add(1)
	sem <- 1
	go func() {
		url_mod := previousParts + "/" + lastPart + "??"
		curl_code_response("/"+lastPart+"??:", options, url_mod)
		<-sem
	}()
	wg.Add(1)
	sem <- 1
	go func() {
		url_mod := previousParts + "/" + lastPart + "//"
		curl_code_response("/"+lastPart+"//:", options, url_mod)
		<-sem
	}()
	wg.Add(1)
	sem <- 1
	go func() {
		url_mod := previousParts + "/" + lastPart + "/"
		curl_code_response("/"+lastPart+"/:", options, url_mod)
		<-sem
	}()
	wg.Add(1)
	sem <- 1
	go func() {
		options_mod := append(options, "--path-as-is")
		url_mod := previousParts + "/./" + lastPart + "/./"
		curl_code_response("/./"+lastPart+"/./:", options_mod, url_mod)
		<-sem
	}()
	wg.Add(1)
	sem <- 1
	go func() {
		url_mod := previousParts + "/" + lastPart + "/.randomstring"
		curl_code_response("/"+lastPart+"/.randomstring:", options, url_mod)
		<-sem
	}()
	wg.Add(1)
	sem <- 1
	go func() {
		options_mod := append(options, "--path-as-is")
		url_mod := previousParts + "/" + lastPart + "..;/"
		curl_code_response("/"+lastPart+"..;/:", options_mod, url_mod)
		<-sem
	}()
	wg.Add(1)
	sem <- 1
	go func() {
		options_mod := append(options, "--path-as-is")
		url_mod := previousParts + "/" + lastPart + "..;"
		curl_code_response("/"+lastPart+"..;:", options_mod, url_mod)
		<-sem
	}()
	wg.Add(1)
	sem <- 1
	go func() {
		options_mod := append(options, "--path-as-is")
		url_mod := previousParts + "/.;/" + lastPart
		curl_code_response("/.;/"+lastPart+":", options_mod, url_mod)
		<-sem
	}()
	wg.Add(1)
	sem <- 1
	go func() {
		options_mod := append(options, "--path-as-is")
		url_mod := previousParts + "/.;/" + lastPart + "/.;/"
		curl_code_response("/.;/"+lastPart+"/.;/:", options_mod, url_mod)
		<-sem
	}()
	wg.Add(1)
	sem <- 1
	go func() {
		options_mod := append(options, "--path-as-is")
		url_mod := previousParts + "/;foo=bar/" + lastPart
		curl_code_response("/;foo=bar/"+lastPart+":", options_mod, url_mod)
		<-sem
	}()
	wg.Wait()
}
