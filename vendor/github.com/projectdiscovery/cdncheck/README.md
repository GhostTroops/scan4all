<h1 align="center">
 cdncheck
<br>
</h1>


<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/cdncheck"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/cdncheck"></a>
<a href="https://pkg.go.dev/github.com/projectdiscovery/cdncheck/pkg/cdncheck"><img src="https://img.shields.io/badge/go-reference-blue"></a>
<a href="https://github.com/projectdiscovery/cdncheck/releases"><img src="https://img.shields.io/github/release/projectdiscovery/cdncheck"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>

</p>

<pre align="center">
<b>
cdncheck is a tool for identifying the technology associated with dns / ip network addresses.
</b>
</pre>

![image](https://user-images.githubusercontent.com/8293321/234400462-9474a3b6-4f9f-443b-a5c7-15120d6cef5f.png)

## Features

- **CDN**, **CLOUD** and **WAF** Detection
- **Easy to use as library**
- Easily extendable providers
- IP, DNS input support
- Text, JSONL output
- Filters on output

# Installation

**cdncheck** requires **go1.19** to install successfully. Run the following command to install the latest version:

```sh
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
```

# Usage

```sh
cdncheck -h
```

This will display help for the tool. Here are all the switches it supports.

```yaml
Usage:
  ./cdncheck [flags]

Flags:
INPUT:
   -i, -input string[]  list of ip / dns to process

DETECTION:
   -cdn    display only cdn in cli output
   -cloud  display only cloud in cli output
   -waf    display only waf in cli output

MATCHER:
   -mcdn, -match-cdn string[]      match host with specified cdn provider (cloudfront, fastly, google, leaseweb)
   -mcloud, -match-cloud string[]  match host with specified cloud provider (aws, google, oracle)
   -mwaf, -match-waf string[]      match host with specified waf provider (cloudflare, incapsula, sucuri, akamai)

FILTER:
   -fcdn, -filter-cdn string[]      filter host with specified cdn provider (cloudfront, fastly, google, leaseweb)
   -fcloud, -filter-cloud string[]  filter host with specified cloud provider (aws, google, oracle)
   -fwaf, -filter-waf string[]      filter host with specified waf provider (cloudflare, incapsula, sucuri, akamai)

OUTPUT:
   -resp               display technology name in cli output
   -o, -output string  write output in plain format to file
   -v, -verbose        display verbose output
   -j, -jsonl          write output in json(line) format
   -nc, -no-color      disable colors in cli output
   -version            display version of the project
   -silent             only display results in output

CONFIG:
   -r, -resolver string[]  list of resolvers to use (file or comma separated)
   -e, -exclude            exclude detected ip from output
   -retry int              maximum number of retries for dns resolution (must be at least 1) (default 2)

UPDATE:
   -up, -update                 update cdncheck to latest version
   -duc, -disable-update-check  disable automatic cdncheck update check
```

## How to add new providers?

[provider.yaml](cmd/generate-index/provider.yaml) file contains list of **CDN**, **WAF** and **Cloud** providers. The list contains **URLs**, **ASNs** and **CIDRs** which are then compiled into a final `sources_data.json` file using `generate-index` program.

Example of `provider.yaml` file - 

```yaml
cdn:
  # asn contains the ASN numbers for providers
  asn:
    leaseweb:
      - AS60626

  # urls contains a list of URLs for CDN providers
  urls:
    cloudfront:
      - https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips
    fastly:
      - https://api.fastly.com/public-ip-list

  # cidr contains the CIDR ranges for providers
  cidr:
    akamai:
      - "23.235.32.0/20"
      - "43.249.72.0/22"
      - "103.244.50.0/24"
      - "103.245.222.0/23"
      - "103.245.224.0/24"
      - "104.156.80.0/20"
```

New providers which can be scraped from a URL, ASN or a list of static CIDR can be added to `provider.yaml` file by following simple steps as listed below:

- Fork the GitHub repository containing the `cmd/generate-index/provider.yaml` file.
- Clone your forked repository to your local machine and navigate to the `cmd/generate-index` directory.
- Open the `provider.yaml` file and locate the section for the type of provider you want to add (CDN, WAF, or Cloud).
- Add the new provider's information to the appropriate section in the `provider.yaml` file.
- Commit your changes with a descriptive commit message.
- Push your changes to your forked repository on GitHub.
- Open a pull request to the original repository with your changes.


### Other providers

**CNAME** and **Wappalyzer** based additions can be done in [other.go](other.go) file. Just simply add the values to the variables and you're good to go.

```go
// cdnCnameDomains contains a map of CNAME to domains to cdns
var cdnCnameDomains = map[string]string{
	"cloudfront.net":         "amazon",
	"amazonaws.com":          "amazon",
    ...
}

// cdnWappalyzerTechnologies contains a map of wappalyzer technologies to cdns
var cdnWappalyzerTechnologies = map[string]string{
	"imperva":    "imperva",
	"incapsula":  "incapsula",
	...
}
```

## cdncheck as library

Helper library that checks if a given IP is running on Cloud / CDN / WAF.

The library can be used by importing `github.com/projectdiscovery/cdncheck`. here follows a basic example:

```go
package main

import (
	"fmt"
	"net"
	"github.com/projectdiscovery/cdncheck"
)

func main() {
	client := cdncheck.New()
	ip := net.ParseIP("173.245.48.12")

	// checks if an IP is contained in the cdn denylist
	matched, val, err := client.CheckCDN(ip)
	if err != nil {
		panic(err)
	}

	if matched {
		fmt.Printf("%v is a %v\n", ip, val)
	} else {
		fmt.Printf("%v is not a CDN\n", ip)
	}

	// checks if an IP is contained in the cloud denylist
	matched, val, err = client.CheckCloud(ip)
	if err != nil {
		panic(err)
	}

	if matched {
		fmt.Printf("%v is a %v\n", ip, val)
	} else {
		fmt.Printf("%v is not a Cloud\n", ip)
	}

	// checks if an IP is contained in the waf denylist
	matched, val, err = client.CheckWAF(ip)
	if err != nil {
		panic(err)
	}

	if matched {
		fmt.Printf("%v WAF is %v\n", ip, val)
	} else {
		fmt.Printf("%v is not a WAF\n", ip)
	}
}
```

--------

<div align="center">

**cdncheck** is made with ❤️ by the [projectdiscovery](https://projectdiscovery.io) team and distributed under [MIT License](LICENSE.md).


<a href="https://discord.gg/projectdiscovery"><img src="https://raw.githubusercontent.com/projectdiscovery/nuclei-burp-plugin/main/static/join-discord.png" width="300" alt="Join Discord"></a>

</div>