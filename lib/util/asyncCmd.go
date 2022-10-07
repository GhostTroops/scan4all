package util

import (
	"bufio"
	"io"
	"os"
	"os/exec"
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
	cmd := r.Command(szCmd, args...)
	//log.Println(cmd.Args)
	var err error
	cmdReader, err := cmd.StdoutPipe()
	if nil != err {
		return err
	}
	done := make(chan struct{}, 2)
	var fnSc1 = func(bs *bufio.Scanner) {
		defer func() {
			done <- struct{}{}
		}()
		for bs.Scan() {
			select {
			case <-Ctx_global.Done():
				cmd.Exit()
				return
			default:
				fnCbk(bs.Text())
			}

		}
	}
	var bDoErr = false
	if bDoErr {
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return err
		}
		scanner1 := bufio.NewScanner(stderr)
		go fnSc1(scanner1)
	}
	//cmd.stdin.Close()
	//go io.Copy(io.Discard, stderr)
	scanner := bufio.NewScanner(cmdReader)
	go fnSc1(scanner)
	err = cmd.Start()
	if err != nil {
		return err
	}
	err = cmd.Wait()
	<-done
	if bDoErr {
		<-done
	}
	return err
}

// 异步执行命令
func AsynCmd(fnCbk func(line string), szCmd string, args ...string) error {
	c1 := new(Cmd)
	err := c1.AsynCmd(fnCbk, szCmd, args...)
	c1.Exit()
	return err
}
