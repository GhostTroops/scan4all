package pkg

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"sync"
)

func DoPipCmd4Buf(buf *bytes.Buffer, cbk func(io.Reader, []string), commands ...[]string) {
	DoPipCmd(bytes.NewReader(buf.Bytes()), cbk, commands...)
}

/*
执行各种命令
每一参数是一个数组，exec.Command(x...)命令的所有参数
需要将前一个命令的输出作为第一个命令的输入；第一个命令没有输入，只有参数
*/
func DoPipCmd(prevReader io.Reader, cbk func(io.Reader, []string), commands ...[]string) {
	var wg sync.WaitGroup
	defer wg.Wait()

	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)

		if prevReader != nil {
			cmd.Stdin = prevReader
		}

		pipeReader, pipeWriter := io.Pipe()
		cmd.Stdout = io.MultiWriter(pipeWriter)

		cbkReader, cbkWriter := io.Pipe()

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer pipeWriter.Close()
			defer cbkWriter.Close()

			teeReader := io.TeeReader(pipeReader, cbkWriter)

			go cbk(teeReader, args)
			if err := cmd.Run(); err != nil {
				fmt.Printf("Error executing command '%s': %v\n", args[0], err)
			}
		}()

		prevReader = cbkReader
	}
}
