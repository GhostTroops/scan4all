package utils

import (
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// E if the last arg is error, panic it
func E(args ...interface{}) []interface{} {
	err, ok := args[len(args)-1].(error)
	if ok {
		panic(err)
	}
	return args
}

// RandBytes generate random bytes with specified byte length
func RandBytes(len int) []byte {
	b := make([]byte, len)
	_, _ = rand.Read(b)
	return b
}

// MkdirOptions ...
type MkdirOptions struct {
	Perm os.FileMode
}

// Mkdir makes dir recursively
func Mkdir(path string, options *MkdirOptions) error {
	if options == nil {
		options = &MkdirOptions{
			Perm: 0775,
		}
	}

	return os.MkdirAll(path, options.Perm)
}

// OutputFileOptions ...
type OutputFileOptions struct {
	DirPerm    os.FileMode
	FilePerm   os.FileMode
	JSONPrefix string
	JSONIndent string
}

// OutputFile auto creates file if not exists, it will try to detect the data type and
// auto output binary, string or json
func OutputFile(p string, data interface{}, options *OutputFileOptions) error {
	if options == nil {
		options = &OutputFileOptions{0775, 0664, "", "    "}
	}

	dir := filepath.Dir(p)
	_ = Mkdir(dir, &MkdirOptions{Perm: options.DirPerm})

	var bin []byte

	switch t := data.(type) {
	case []byte:
		bin = t
	case string:
		bin = []byte(t)
	default:
		var err error
		bin, err = json.MarshalIndent(data, options.JSONPrefix, options.JSONIndent)

		if err != nil {
			return err
		}
	}

	return ioutil.WriteFile(p, bin, options.FilePerm)
}

// FileExists checks if file exists, only for file, not for dir
func FileExists(path string) bool {
	info, err := os.Stat(path)

	if err != nil {
		return false
	}

	if info.IsDir() {
		return false
	}

	return true
}

// Sleep the goroutine for specified seconds, such as 2.3 seconds
func Sleep(seconds float64) {
	d := time.Duration(seconds * float64(time.Second))
	time.Sleep(d)
}

// ReadFile reads file as bytes
func ReadFile(p string) ([]byte, error) {
	return ioutil.ReadFile(p)
}

// ReadJSON reads file as json
func ReadJSON(p string, data interface{}) error {
	bin, err := ReadFile(p)

	if err != nil {
		return err
	}

	return json.Unmarshal(bin, data)
}

// MustToJSONBytes encode data to json bytes
func MustToJSONBytes(data interface{}) []byte {
	bytes, err := json.Marshal(data)
	E(err)
	return bytes
}

// MustToJSON encode data to json string
func MustToJSON(data interface{}) string {
	return string(MustToJSONBytes(data))
}

// Exec cmd
func Exec(cmd, dir string, args ...string) {
	c := exec.Command(cmd, args...)
	c.Dir = dir
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	E(c.Run())
}
