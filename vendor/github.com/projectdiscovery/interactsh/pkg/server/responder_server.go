package server

import (
	"bytes"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/filewatcher"
	"github.com/projectdiscovery/stringsutil"
)

var responderMonitorList map[string]string = map[string]string{
	// search term : extract after
	"NTLMv2-SSP Hash": "NTLMv2-SSP Hash     : ",
}

// ResponderServer is a Responder wrapper server instance
type ResponderServer struct {
	options   *Options
	LogFile   string
	ipAddress net.IP
	cmd       *exec.Cmd
	tmpFolder string
}

// NewResponderServer returns a new SMB server.
func NewResponderServer(options *Options) (*ResponderServer, error) {
	server := &ResponderServer{
		options:   options,
		ipAddress: net.ParseIP(options.IPAddress),
	}
	return server, nil
}

// ListenAndServe listens on various responder ports
func (h *ResponderServer) ListenAndServe(responderAlive chan bool) error {
	responderAlive <- true
	defer func() {
		responderAlive <- false
	}()
	tmpFolder, err := ioutil.TempDir("", "")
	if err != nil {
		return err
	}
	h.tmpFolder = tmpFolder
	// execute dockerized responder
	cmdLine := "docker run -p 137:137/udp -p  138:138/udp -p 389:389 -p 1433:1433 -p 1434:1434/udp -p 135:135 -p 139:139 -p 445:445 -p 21:21 -p 3141:3141 -p 110:110 -p 3128:3128 -p 5355:5355/udp -v " + h.tmpFolder + ":/opt/Responder/logs --rm interactsh:latest"
	args := strings.Fields(cmdLine)
	h.cmd = exec.Command(args[0], args[1:]...)
	err = h.cmd.Start()
	if err != nil {
		return err
	}

	// watch output file
	outputFile := filepath.Join(h.tmpFolder, "Responder-Session.log")
	// wait until the file is created
	for !fileutil.FileExists(outputFile) {
		time.Sleep(1 * time.Second)
	}
	fw, err := filewatcher.New(filewatcher.Options{
		Interval: time.Duration(5 * time.Second),
		File:     outputFile,
	})
	if err != nil {
		return err
	}

	ch, err := fw.Watch()
	if err != nil {
		return err
	}

	// This fetches the content at each change.
	go func() {
		for data := range ch {
			for searchTerm, extractAfter := range responderMonitorList {
				if strings.Contains(data, searchTerm) {
					responderData, err := stringsutil.After(data, extractAfter)
					if err != nil {
						gologger.Warning().Msgf("Could not get responder interaction: %s\n", err)
						continue
					}

					// Correlation id doesn't apply here, we skip encryption
					interaction := &Interaction{
						Protocol:   "responder",
						RawRequest: responderData,
						Timestamp:  time.Now(),
					}
					buffer := &bytes.Buffer{}
					if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
						gologger.Warning().Msgf("Could not encode responder interaction: %s\n", err)
					} else {
						gologger.Debug().Msgf("Responder Interaction: \n%s\n", buffer.String())
						if err := h.options.Storage.AddInteractionWithId(h.options.Token, buffer.Bytes()); err != nil {
							gologger.Warning().Msgf("Could not store dns interaction: %s\n", err)
						}
					}
				}
			}
		}
	}()

	return h.cmd.Wait()
}

func (h *ResponderServer) Close() {
	_ = h.cmd.Process.Kill()
	if fileutil.FolderExists(h.tmpFolder) {
		os.RemoveAll(h.tmpFolder)
	}
}
