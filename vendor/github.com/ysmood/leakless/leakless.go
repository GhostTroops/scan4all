//go:generate go run ./cmd/pack

package leakless

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ysmood/leakless/pkg/shared"
	"github.com/ysmood/leakless/pkg/utils"
)

var leaklessBinaries = map[string]string{}

// Launcher struct
type Launcher struct {
	// Lock for leakless.LockPort, default is 2978
	Lock int

	pid chan int
	err string
}

// New leakless instance
func New() *Launcher {
	return &Launcher{
		Lock: 2978,
		pid:  make(chan int),
	}
}

// Command will try to download the leakless bin and prefix the exec.Cmd with the leakless options.
func (l *Launcher) Command(name string, arg ...string) *exec.Cmd {
	bin := ""
	func() {
		defer LockPort(l.Lock)()
		bin = GetLeaklessBin()
	}()

	uid := fmt.Sprintf("%x", utils.RandBytes(16))
	addr := l.serve(uid)

	arg = append([]string{uid, addr, name}, arg...)
	return exec.Command(bin, arg...)
}

// Pid signals the pid of the guarded sub-process. The channel may never receive the pid.
func (l *Launcher) Pid() chan int {
	return l.pid
}

// Err message from the guard process
func (l *Launcher) Err() string {
	return l.err
}

func (l *Launcher) serve(uid string) string {
	srv, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic("[leakless] serve error: " + err.Error())
	}

	go func() {
		defer func() { _ = srv.Close() }()

		conn, err := srv.Accept()
		if err != nil {
			l.err = err.Error()
			l.pid <- 0
			return
		}

		enc := json.NewEncoder(conn)
		err = enc.Encode(shared.Message{UID: uid})
		if err != nil {
			l.err = err.Error()
			l.pid <- 0
			return
		}

		dec := json.NewDecoder(conn)
		var msg shared.Message
		err = dec.Decode(&msg)
		if err == nil {
			l.err = msg.Error
			l.pid <- msg.PID
		}
		_ = dec.Decode(&msg)
	}()

	return srv.Addr().String()
}

var leaklessDir = filepath.Join(os.TempDir(), "leakless-"+shared.Version)

// GetLeaklessBin returns the executable path of the guard, if it doesn't exists create one.
func GetLeaklessBin() string {
	bin := filepath.Join(leaklessDir, "leakless")

	if runtime.GOOS == "windows" {
		bin += ".exe"
	}

	if !utils.FileExists(bin) {
		name := utils.GetTarget().BinName()
		raw, err := base64.StdEncoding.DecodeString(leaklessBinaries[name])
		utils.E(err)
		gr, err := gzip.NewReader(bytes.NewBuffer(raw))
		utils.E(err)
		data, err := ioutil.ReadAll(gr)
		utils.E(err)
		utils.E(gr.Close())

		err = utils.OutputFile(bin, data, nil)
		utils.E(err)
		utils.E(os.Chmod(bin, 0755))
	}

	return bin
}

// Support returns true if the OS is supported by leakless.
func Support() bool {
	_, has := leaklessBinaries[utils.GetTarget().BinName()]
	return has
}

// LockPort uses a tcp port to create a mutex lock for cross-process locking.
// It will poll the port to check if it's free.
func LockPort(port int) func() {
	var l net.Listener
	for {
		var err error
		l, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			break
		}
		time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
	}

	return func() {
		_ = l.Close()
	}
}
