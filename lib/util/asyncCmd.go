package util

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// KillTimeout timeout for kill signal when exiting a Cmd
var KillTimeout = 1000 * time.Millisecond

// InterruptTimeout timeout for interrupt signal when exiting a Cmd
var InterruptTimeout = 200 * time.Millisecond

type Cmd struct {
	*exec.Cmd
	stdin io.WriteCloser
}

func (cmd *Cmd) Command(name string, arg ...string) *Cmd {
	cmd.Cmd = exec.Command(name, arg...)
	cmd.stdin, _ = cmd.Cmd.StdinPipe()
	//cmd.stdin.Write([]byte("\n\n"))
	return cmd
}

// Interrupt sends an os.Interrupt to the process if running
func (cmd *Cmd) Interrupt() {
	if cmd.Process != nil {
		cmd.Process.Signal(os.Interrupt)
	}
}
func (cmd *Cmd) Start() error {
	return cmd.Cmd.Start()
}

func (cmd *Cmd) Exit() error {
	// Create exit timers
	interruptTimer := time.AfterFunc(InterruptTimeout, func() {
		cmd.Cmd.Process.Signal(os.Interrupt)
	})
	killTimer := time.AfterFunc(KillTimeout, func() {
		cmd.Cmd.Process.Kill()
	})

	// Wait for exit
	err := cmd.Cmd.Wait()

	interruptTimer.Stop()
	killTimer.Stop()

	return err
}

// 基于回调获取输入
func (r *Cmd) WriteInput4Cbk(fnCbk func() *string) {
	for x := fnCbk(); ; {
		if x != nil {
			r.WriteInput(*x)
		} else {
			break
		}
	}
}

// write input, for interactive
func (r *Cmd) WriteInput(args ...string) {
	if nil != r.stdin {
		for _, i := range args {
			io.WriteString(r.stdin, i)
		}
	}
}

func (r *Cmd) AsynCmd(fnCbk func(line string), szCmd string, args ...string) error {
	cmd := exec.CommandContext(Ctx_global, szCmd, args...)
	cmd.WaitDelay = KillTimeout

	stdout, err := cmd.StdoutPipe()
	if nil != err {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	var readers sync.WaitGroup
	readers.Add(2)
	var scanErr, stderrErr error
	go func() {
		defer readers.Done()
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			fnCbk(scanner.Text())
		}
		scanErr = scanner.Err()
	}()
	go func() {
		defer readers.Done()
		_, stderrErr = io.Copy(io.Discard, stderr)
	}()

	waitErr := cmd.Wait()
	readers.Wait()
	if waitErr != nil {
		return waitErr
	}
	if scanErr != nil {
		return scanErr
	}
	return stderrErr
}

// 异步执行命令
func AsynCmd(fnCbk func(line string), szCmd string, args ...string) error {
	return new(Cmd).AsynCmd(fnCbk, szCmd, args...)
}
