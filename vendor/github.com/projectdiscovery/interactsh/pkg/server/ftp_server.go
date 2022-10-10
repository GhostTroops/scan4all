package server

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	ftpserver "goftp.io/server/v2"
	"goftp.io/server/v2/driver/file"
)

// FTPServer is a ftp server instance
type FTPServer struct {
	options   *Options
	ftpServer *ftpserver.Server
}

// NewFTPServer returns a new TLS & Non-TLS FTP server.
func NewFTPServer(options *Options) (*FTPServer, error) {
	server := &FTPServer{options: options}

	ftpFolder := options.FTPDirectory
	if ftpFolder == "" {
		var err error
		ftpFolder, err = os.MkdirTemp("", "")
		if err != nil {
			return nil, err
		}
	}

	driver, err := file.NewDriver(ftpFolder)
	if err != nil {
		return nil, err
	}

	nopDriver := NewNopDriver(driver)

	opt := &ftpserver.Options{
		Name:   "interactsh-ftp",
		Driver: nopDriver,
		Port:   options.FtpPort,
		Perm:   ftpserver.NewSimplePerm("root", "root"),
		Logger: server,
		Auth:   &NopAuth{},
	}

	// start ftp server
	ftpServer, err := ftpserver.NewServer(opt)
	if err != nil {
		return nil, err
	}
	server.ftpServer = ftpServer
	ftpServer.RegisterNotifer(server)

	return server, nil
}

// ListenAndServe listens on smtp and/or smtps ports for the server.
func (h *FTPServer) ListenAndServe(tlsConfig *tls.Config, ftpAlive chan bool) {
	ftpAlive <- true
	if err := h.ftpServer.ListenAndServe(); err != nil {
		gologger.Error().Msgf("Could not serve ftp on port 21: %s\n", err)
		ftpAlive <- false
	}
}

func (h *FTPServer) Close() {
	_ = h.ftpServer.Shutdown()
}

func (h *FTPServer) recordInteraction(remoteAddress, data string) {
	atomic.AddUint64(&h.options.Stats.Ftp, 1)

	if data == "" {
		return
	}
	interaction := &Interaction{
		RemoteAddress: remoteAddress,
		Protocol:      "ftp",
		RawRequest:    data,
		Timestamp:     time.Now(),
	}
	buffer := &bytes.Buffer{}
	if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
		gologger.Warning().Msgf("Could not encode ftp interaction: %s\n", err)
	} else {
		gologger.Debug().Msgf("FTP Interaction: \n%s\n", buffer.String())
		if err := h.options.Storage.AddInteractionWithId(h.options.Token, buffer.Bytes()); err != nil {
			gologger.Warning().Msgf("Could not store ftp interaction: %s\n", err)
		}
	}
}

func (h *FTPServer) Print(sessionID string, message interface{})              {}
func (h *FTPServer) Printf(sessionID string, format string, v ...interface{}) {}
func (h *FTPServer) PrintCommand(sessionID string, command string, params string) {
	h.Print(sessionID, fmt.Sprintf("%s %s", command, params))
}
func (h *FTPServer) PrintResponse(sessionID string, code int, message string) {
	h.Print(sessionID, fmt.Sprintf("%d %s", code, message))
}

func (h *FTPServer) BeforeLoginUser(ctx *ftpserver.Context, userName string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString(userName + " logging in")
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) BeforePutFile(ctx *ftpserver.Context, dstPath string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("uploading " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) BeforeDeleteFile(ctx *ftpserver.Context, dstPath string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("deleting " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) BeforeChangeCurDir(ctx *ftpserver.Context, oldCurDir, newCurDir string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("changing directory from " + oldCurDir + " to " + newCurDir)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) BeforeCreateDir(ctx *ftpserver.Context, dstPath string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("creating directory " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) BeforeDeleteDir(ctx *ftpserver.Context, dstPath string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("deleting directory " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) BeforeDownloadFile(ctx *ftpserver.Context, dstPath string) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("downloading file " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) AfterUserLogin(ctx *ftpserver.Context, userName, password string, passMatched bool, err error) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("user " + userName + " logged in with password " + password)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) AfterFilePut(ctx *ftpserver.Context, dstPath string, size int64, err error) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("uploaded " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) AfterFileDeleted(ctx *ftpserver.Context, dstPath string, err error) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("deleted " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) AfterFileDownloaded(ctx *ftpserver.Context, dstPath string, size int64, err error) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("downloaded file " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) AfterCurDirChanged(ctx *ftpserver.Context, oldCurDir, newCurDir string, err error) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("changed directory from " + oldCurDir + " to " + newCurDir)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) AfterDirCreated(ctx *ftpserver.Context, dstPath string, err error) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("created directory " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}
func (h *FTPServer) AfterDirDeleted(ctx *ftpserver.Context, dstPath string, err error) {
	var b strings.Builder
	b.WriteString(ctx.Cmd)
	b.WriteString(" ")
	b.WriteString(ctx.Param)
	b.WriteString("\n")
	b.WriteString("delete directory " + dstPath)
	h.recordInteraction(ctx.Sess.RemoteAddr().String(), b.String())
}

type NopAuth struct{}

func (a *NopAuth) CheckPasswd(ctx *ftpserver.Context, name, pass string) (bool, error) {
	return true, nil
}

type NopDriver struct {
	driver ftpserver.Driver
}

func NewNopDriver(driver ftpserver.Driver) *NopDriver {
	return &NopDriver{driver: driver}
}

func (n *NopDriver) Stat(c *ftpserver.Context, s string) (os.FileInfo, error) {
	return n.driver.Stat(c, s)
}

func (n *NopDriver) ListDir(c *ftpserver.Context, s string, f func(os.FileInfo) error) error {
	return n.driver.ListDir(c, s, f)
}

func (n *NopDriver) DeleteDir(c *ftpserver.Context, s string) error {
	return nil
}

func (n *NopDriver) DeleteFile(c *ftpserver.Context, s string) error {
	return nil
}

func (n *NopDriver) Rename(c *ftpserver.Context, s1 string, s2 string) error {
	return nil
}

func (n *NopDriver) MakeDir(c *ftpserver.Context, s string) error {
	return nil
}

func (n *NopDriver) GetFile(c *ftpserver.Context, s1 string, k int64) (int64, io.ReadCloser, error) {
	return n.driver.GetFile(c, s1, k)
}

func (n *NopDriver) PutFile(c *ftpserver.Context, s string, r io.Reader, k int64) (int64, error) {
	return k, nil
}
