package go_utils

import (
	"bufio"
	"io"
	"log"
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
	log.Println(cmd.Args)
	var err error
	cmdReader, err := cmd.StdoutPipe()
	if nil != err {
		return err
	}
	//stderr, err := cmd.StderrPipe()
	//if err != nil {
	//	return err
	//}

	scanner := bufio.NewScanner(cmdReader)
	done := make(chan struct{}, 1)
	go func() {
		defer func() {
			done <- struct{}{}
		}()
		for scanner.Scan() {
			select {
			case <-Ctx_global.Done():
				cmd.Exit()
				return
			default:
				fnCbk(scanner.Text())
			}

		}
	}()
	err = cmd.Start()
	if err != nil {
		return err
	}
	<-done
	err = cmd.Wait()
	return err
}

// 异步执行命令
func AsynCmd(fnCbk func(line string), szCmd string, args ...string) error {
	return new(Cmd).AsynCmd(fnCbk, szCmd, args...)
}
