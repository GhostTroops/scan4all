package util

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestAsynCmd(t *testing.T) {
	t.Setenv("ASYNC_CMD_HELPER", "1")
	var lines []string
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	err = AsynCmd(func(line string) {
		lines = append(lines, line)
	}, executable, "-test.run=^TestAsynCmdHelper$")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"stdout one", "stdout two"}; !reflect.DeepEqual(lines, want) {
		t.Fatalf("stdout lines = %q, want %q", lines, want)
	}
}

func TestAsynCmdHelper(t *testing.T) {
	if os.Getenv("ASYNC_CMD_HELPER") != "1" {
		return
	}
	_, _ = os.Stdout.WriteString("stdout one\nstdout two\n")
	_, _ = os.Stderr.WriteString(strings.Repeat("stderr output\n", 10000))
	os.Exit(0)
}
