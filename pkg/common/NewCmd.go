package common

import (
	"context"
	util "github.com/hktalent/go-utils"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"time"
)

type AsCmd struct {
	Cmdstr         string
	Cmd            *exec.Cmd
	Timeout        time.Duration
	Wg             *util.SizedWaitGroup
	InputWriterCbk func(io.WriteCloser)
}

func (r *AsCmd) SetTimeout(n time.Duration) *AsCmd {
	r.Timeout = n * time.Second
	return r
}

// StdinPipe returns a pipe that will be connected to the command's
// standard input when the command starts.
// The pipe will be closed automatically after Wait sees the command exit.
// A caller need only call Close to force the pipe to close sooner.
// For example, if the command being run will not exit until standard input
// is closed, the caller must close the pipe.
func (r *AsCmd) GetInput4Writer() io.WriteCloser {
	if w, err := r.Cmd.StdinPipe(); nil == err {
		return w
	} else {
		log.Println(err)
	}
	return nil
}

func (r *AsCmd) GetOut4Reader() io.ReadCloser {
	if r, err := r.Cmd.StdoutPipe(); nil == err {
		return r
	} else {
		log.Println(err)
	}
	return nil
}

func (r *AsCmd) Close() {
	if "" != r.Cmdstr {
		RegCmd(r.Cmdstr, nil)
	}
	if nil != r.Cmd.Process {
		r.Cmd.Process.Kill()
		//r.Cmd.Process.Signal(os.Interrupt)
	}
	r.Cmd = nil
}
func (r *AsCmd) Wait() *AsCmd {
	r.Wg.Wait()
	if nil != r.Cmd.Process {
		if _, err := r.Cmd.Process.Wait(); nil != err {
			log.Println(err)
		}
	}
	//if err := r.Cmd.Wait(); nil != err {
	//	log.Println(err)
	//}
	log.Println("cmd over")
	return r
}
func (r *AsCmd) Start() *AsCmd {
	util.WaitFunc4Wg(r.Wg, func() {
		if 0 < r.Timeout {
			killTimer := time.AfterFunc(r.Timeout, func() {
				r.Cmd.Process.Kill()
			})
			interruptTimer := time.AfterFunc(r.Timeout, func() {
				r.Cmd.Process.Signal(os.Interrupt)
			})
			interruptTimer.Stop()
			killTimer.Stop()
		}

		if err := r.Cmd.Start(); nil != err {
			log.Println(err)
		}
		if err := r.Cmd.Wait(); nil != err {
			log.Println(err)
		}
	})

	return r
}

func NewAsCmd(Wg *util.SizedWaitGroup, iw func(io.WriteCloser)) *AsCmd {
	r := &AsCmd{Wg: Wg, InputWriterCbk: iw}
	return r
}

var re1 = regexp.MustCompile(` +`)

func (r *AsCmd) DoCmdOutLine4Cbk(cbk func(*string), arg ...string) *AsCmd {
	util.WaitFunc4Wg(r.Wg, func() {
		var out = make(chan *string)
		util.WaitFunc4Wg(r.Wg, func() {
			r.DoCmdOutLine(out, arg...)
		})
		for i := range out {
			cbk(i)
		}
		r.Close()
	})
	return r
}

func (r *AsCmd) DoCmdOutLine(out chan *string, arg ...string) *AsCmd {
	r.DoCmd(arg...)
	r1 := r.GetOut4Reader()
	if nil != r1 {
		util.WaitFunc4Wg(r.Wg, func() {
			util.ReadStream4Line(r1, func(s *string) {
				out <- s
			})
			close(out)
		})
	}
	if r.InputWriterCbk != nil {
		// 必须在start之前获取
		iw := r.GetInput4Writer()
		util.WaitFunc4Wg(r.Wg, func() {
			r.InputWriterCbk(iw)
		})
	}
	r.Start()
	return r
}
func (r *AsCmd) DoCmd(arg ...string) *AsCmd {
	if 0 == len(arg) {
		return r
	}
	var a = arg
	if 1 == len(a) {
		r.Cmdstr = a[0]
		a = re1.Split(a[0], -1)
	}
	if 0 < r.Timeout {
		ctx, _ := context.WithTimeout(context.Background(), r.Timeout*time.Second)
		//defer cancel()
		r.Cmd = exec.CommandContext(ctx, a[0], a[1:]...)
	} else {
		r.Cmd = exec.Command(a[0], a[1:]...)
	}
	//r.Cmd.WaitDelay = math.MaxInt64
	r.Cmd.Stderr = io.Discard //os.Stdout //
	return r
}

// 判断给定的命令是否在当前系统中可用
// HaveCmd([]string{"nuclei","httpx","tlsx"}...)
func HaveCmd(s ...string) []bool {
	var a = make([]bool, len(s))
	for i, x := range s {
		if ep, err := exec.LookPath(x); nil != err && "" != ep {
			a[i] = true
		}
	}
	return a
}

func DoCmd4Cbk(szCmd string, cbk func(*string), ipt chan *string) {
	var lk = util.GetLock(szCmd + "_DoCmd4Cbk").Lock()
	defer lk.Unlock()
	var cmdI = GetCmd(szCmd)
	if nil != cmdI {
		for x := range ipt {
			cmdI <- x
		}
		close(ipt)
		return
	}
	RegCmd(szCmd, ipt)
	var wg = util.NewSizedWaitGroup(5000)
	cmd := NewAsCmd(&wg, func(wt io.WriteCloser) {
		defer wt.Close()
		for x := range ipt {
			if "" == *x {
				continue
			}
			wt.Write([]byte(*x + "\n"))
		}
	})
	cmd.DoCmdOutLine4Cbk(func(s *string) {
		util.WaitFunc4Wg(&wg, func() {
			cbk(s)
		})
		//if nil == s { // time.After(5 * time.Second)
		//close(ipt)
		//}
	}, szCmd)
	wg.Wait()
	close(ipt)
}
