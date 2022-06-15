package server

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/filewatcher"
	"github.com/projectdiscovery/stringsutil"
)

var smbMonitorList map[string]string = map[string]string{
	// search term : extract after
	"INFO: ": "INFO: ",
}

// SMBServer is a smb wrapper server instance
type SMBServer struct {
	options   *Options
	LogFile   string
	ipAddress net.IP
	cmd       *exec.Cmd
	tmpFile   string
}

// NewSMBServer returns a new SMB server.
func NewSMBServer(options *Options) (*SMBServer, error) {
	server := &SMBServer{
		options:   options,
		ipAddress: net.ParseIP(options.IPAddress),
	}
	return server, nil
}

// ListenAndServe listens on smb port
func (h *SMBServer) ListenAndServe(smbAlive chan bool) error {
	smbAlive <- true
	defer func() {
		smbAlive <- false
	}()
	tmpFile, err := ioutil.TempFile("", "")
	if err != nil {
		return err
	}
	h.tmpFile = tmpFile.Name()
	tmpFile.Close()
	// execute smb_server.py - only works with ./interactsh-server
	cmdLine := fmt.Sprintf("python3 smb_server.py %s %d", h.tmpFile, h.options.SmbPort)
	args := strings.Fields(cmdLine)
	h.cmd = exec.Command(args[0], args[1:]...)
	err = h.cmd.Start()
	if err != nil {
		return err
	}

	// watch output file
	outputFile := h.tmpFile
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
			for searchTerm, extractAfter := range smbMonitorList {
				if strings.Contains(data, searchTerm) {
					smbData := stringsutil.After(data, extractAfter)

					// Correlation id doesn't apply here, we skip encryption
					interaction := &Interaction{
						Protocol:   "smb",
						RawRequest: smbData,
						Timestamp:  time.Now(),
					}
					buffer := &bytes.Buffer{}
					if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
						gologger.Warning().Msgf("Could not encode smb interaction: %s\n", err)
					} else {
						gologger.Debug().Msgf("SMB Interaction: \n%s\n", buffer.String())
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

func (h *SMBServer) Close() {
	_ = h.cmd.Process.Kill()
	if fileutil.FileExists(h.tmpFile) {
		os.RemoveAll(h.tmpFile)
	}
}
