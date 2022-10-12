package runner

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
)

func (r *Runner) handleNmap() error {
	// command from CLI
	command := r.options.NmapCLI
	hasCLI := r.options.NmapCLI != ""
	if hasCLI {
		var ipsPorts []*result.HostResult
		// build a list of all targets
		for hostResult := range r.scanner.ScanResults.GetIPsPorts() {
			ipsPorts = append(ipsPorts, hostResult)
		}

		// sort by number of ports
		sort.Slice(ipsPorts, func(i, j int) bool {
			return len(ipsPorts[i].Ports) < len(ipsPorts[j].Ports)
		})

		// suggests commands grouping ips in pseudo-exp ranges
		// 0 - 100 ports
		// 100 - 1000 ports
		// 1000 - 10000 ports
		// 10000 - 60000 ports
		ranges := make(map[int][]*result.HostResult) // for better readability
		// collect the indexes corresponding to ranges changes
		for _, ipPorts := range ipsPorts {
			length := len(ipPorts.Ports)
			var index int
			switch {
			case length > 100 && length < 1000:
				index = 1
			case length >= 1000 && length < 10000:
				index = 2
			case length >= 10000:
				index = 3
			default:
				index = 0
			}
			ranges[index] = append(ranges[index], ipPorts)
		}

		for _, rang := range ranges {
			args := strings.Split(command, " ")
			var (
				ips   []string
				ports []string
			)
			allports := make(map[int]struct{})
			for _, ipPorts := range rang {
				ips = append(ips, ipPorts.IP)
				for _, pp := range ipPorts.Ports {
					allports[pp] = struct{}{}
				}
			}
			for p := range allports {
				ports = append(ports, fmt.Sprintf("%d", p))
			}

			// if we have no open ports we avoid running nmap
			if len(ports) == 0 {
				continue
			}

			portsStr := strings.Join(ports, ",")
			ipsStr := strings.Join(ips, " ")

			args = append(args, "-p", portsStr)
			args = append(args, ips...)

			// if the command is not executable, we just suggest it
			commandCanBeExecuted := isCommandExecutable(args)

			// if requested via config file or via cli
			if (r.options.Nmap || hasCLI) && commandCanBeExecuted {
				gologger.Info().Msgf("Running nmap command: %s -p %s %s", command, portsStr, ipsStr)
				cmd := exec.Command(args[0], args[1:]...)
				cmd.Stdout = os.Stdout
				err := cmd.Run()
				if err != nil {
					errMsg := errors.Wrap(err, "Could not run nmap command")
					gologger.Error().Msgf(errMsg.Error())
					return errMsg
				}
			} else {
				gologger.Info().Msgf("Suggested nmap command: %s -p %s %s", command, portsStr, ipsStr)
			}
		}
	}

	return nil
}

func isCommandExecutable(args []string) bool {
	commandLength := calculateCmdLength(args)
	if isWindows() {
		// windows has a hard limit of
		// - 2048 characters in XP
		// - 32768 characters in Win7
		return commandLength < 2048
	}
	// linux and darwin
	return true
}

func calculateCmdLength(args []string) int {
	var commandLength int
	for _, arg := range args {
		commandLength += len(arg)
		commandLength += 1 // space character
	}
	return commandLength
}
