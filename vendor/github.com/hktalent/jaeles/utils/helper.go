package utils

import (
	"bufio"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/go-homedir"
)

// StrToInt string to int
func StrToInt(data string) int {
	i, err := strconv.Atoi(data)
	if err != nil {
		return 0
	}
	return i
}

// GetOSEnv get enviroment variable
func GetOSEnv(name string) string {
	varibale, ok := os.LookupEnv(name)
	if !ok {
		return name
	}
	return varibale
}

// MakeDir just make a folder
func MakeDir(folder string) {
	os.MkdirAll(folder, 0750)
}

// GetCurrentDay get current day
func GetCurrentDay() string {
	currentTime := time.Now()
	return fmt.Sprintf("%v", currentTime.Format("2006-01-02_3:4:5"))
}

// NormalizePath the path
func NormalizePath(path string) string {
	if strings.HasPrefix(path, "~") {
		path, _ = homedir.Expand(path)
	}
	return path
}

// FileLength count len of file
func FileLength(filename string) int {
	filename = NormalizePath(filename)
	return len(ReadingLines(filename))
}

// DirLength count len of file
func DirLength(dir string) int {
	dir = NormalizePath(dir)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return 0
	}
	return len(files)
}

// GetFileContent Reading file and return content of it
func GetFileContent(filename string) string {
	var result string
	if strings.Contains(filename, "~") {
		filename, _ = homedir.Expand(filename)
	}
	file, err := os.Open(filename)
	if err != nil {
		return result
	}
	defer file.Close()
	b, err := ioutil.ReadAll(file)
	if err != nil {
		return result
	}
	return string(b)
}

// ReadingLines Reading file and return content as []string
func ReadingLines(filename string) []string {
	var result []string
	if strings.HasPrefix(filename, "~") {
		filename, _ = homedir.Expand(filename)
	}
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		return result
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		val := scanner.Text()
		if val == "" {
			continue
		}
		result = append(result, val)
	}

	if err := scanner.Err(); err != nil {
		return result
	}
	return result
}

// ReadingFileUnique Reading file and return content as []string
func ReadingFileUnique(filename string) []string {
	var result []string
	if strings.Contains(filename, "~") {
		filename, _ = homedir.Expand(filename)
	}
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		return result
	}

	unique := true
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		val := scanner.Text()
		// unique stuff
		if val == "" {
			continue
		}
		if seen[val] && unique {
			continue
		}

		if unique {
			seen[val] = true
			result = append(result, val)
		}
	}

	if err := scanner.Err(); err != nil {
		return result
	}
	return result
}

// WriteToFile write string to a file
func WriteToFile(filename string, data string) (string, error) {
	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	_, err = io.WriteString(file, data+"\n")
	if err != nil {
		return "", err
	}
	return filename, file.Sync()
}

// AppendToContent append string to a file
func AppendToContent(filename string, data string) (string, error) {
	// If the file doesn't exist, create it, or append to the file
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return "", err
	}
	if _, err := f.Write([]byte(data + "\n")); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return filename, nil
}

// FileExists check if file is exist or not
func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

// FolderExists check if file is exist or not
func FolderExists(foldername string) bool {
	foldername = NormalizePath(foldername)
	if _, err := os.Stat(foldername); os.IsNotExist(err) {
		return false
	}
	return true
}

// GetFileNames get all file name with extension
func GetFileNames(dir string, ext string) []string {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	}

	var files []string
	filepath.Walk(dir, func(path string, f os.FileInfo, _ error) error {
		if !f.IsDir() {
			if strings.HasSuffix(f.Name(), ext) {
				filename, _ := filepath.Abs(path)
				files = append(files, filename)
			}
		}
		return nil
	})
	return files
}

// IsJSON check if string is JSON or not
func IsJSON(str string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(str), &js) == nil
}

// GetTS get current timestamp and return a string
func GetTS() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

// GenHash gen SHA1 hash from string
func GenHash(text string) string {
	h := sha1.New()
	h.Write([]byte(text))
	hashed := h.Sum(nil)
	return fmt.Sprintf("%x", hashed)
}

// CopyDir copy directory to dest
func CopyDir(src string, dst string) error {
	var err error
	var fds []os.FileInfo
	var srcInfo os.FileInfo

	if srcInfo, err = os.Stat(src); err != nil {
		return err
	}

	if err = os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return err
	}

	if fds, err = ioutil.ReadDir(src); err != nil {
		return err
	}
	for _, fd := range fds {
		srcfp := path.Join(src, fd.Name())
		dstfp := path.Join(dst, fd.Name())

		if fd.IsDir() {
			if err = CopyDir(srcfp, dstfp); err != nil {
				fmt.Println(err)
			}
		} else {
			if err = CopyFile(srcfp, dstfp); err != nil {
				fmt.Println(err)
			}
		}
	}
	return nil
}

// CopyFile copies a single file from src to dst
func CopyFile(src, dst string) error {
	var err error
	var srcfd *os.File
	var dstfd *os.File
	var srcinfo os.FileInfo

	if srcfd, err = os.Open(src); err != nil {
		return err
	}
	defer srcfd.Close()

	if dstfd, err = os.Create(dst); err != nil {
		return err
	}
	defer dstfd.Close()

	if _, err = io.Copy(dstfd, srcfd); err != nil {
		return err
	}
	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}
	return os.Chmod(dst, srcinfo.Mode())
}

// ExpandLength make slice to length
func ExpandLength(list []string, length int) []string {
	c := []string{}
	for i := 1; i <= length; i++ {
		c = append(c, list[i%len(list)])
	}
	return c
}

// StartWithNum check if string start with number
func StartWithNum(raw string) bool {
	r, err := regexp.Compile("^[0-9].*")
	if err != nil {
		return false
	}
	return r.MatchString(raw)
}

// StripName strip a file name
func StripName(raw string) string {
	return strings.Replace(raw, "/", "_", -1)
}

// MoveFolder move folder
func MoveFolder(src string, dest string) {
	os.Rename(NormalizePath(src), NormalizePath(dest))
}

// GetFileSize get file size of a file in GB
func GetFileSize(src string) float64 {
	var sizeGB float64
	fi, err := os.Stat(NormalizePath(src))
	if err != nil {
		return sizeGB
	}
	// get the size
	size := fi.Size()
	sizeGB = float64(size) / (1024 * 1024 * 1024)
	return sizeGB
}

// ChunkFileByPart chunk file to multiple part
func ChunkFileByPart(source string, chunk int) [][]string {
	var divided [][]string
	data := ReadingLines(source)
	if len(data) <= 0 || chunk > len(data) {
		if len(data) > 0 {
			divided = append(divided, data)
		}
		return divided
	}

	chunkSize := (len(data) + chunk - 1) / chunk
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}

		divided = append(divided, data[i:end])
	}
	return divided
}

// ChunkFileBySize chunk file to multiple part
func ChunkFileBySize(source string, chunk int) [][]string {
	var divided [][]string
	data := ReadingLines(source)
	if len(data) <= 0 || chunk > len(data) {
		if len(data) > 0 {
			divided = append(divided, data)
		}
		return divided
	}

	chunkSize := chunk
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}

		divided = append(divided, data[i:end])
	}
	return divided
}

func PromptConfirm(s string) bool {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s [y/n]: ", s)

		response, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" {
			return true
		} else if response == "n" || response == "no" {
			return false
		}
	}
}

func JoinURL(raw string, suffix string) string {
	u, err := url.Parse(raw)
	if err != nil {
		if strings.HasSuffix(raw, "/") {
			return fmt.Sprintf("%s%s", raw, suffix)
		} else {
			return fmt.Sprintf("%s/%s", raw, suffix)
		}
	}

	u.Path = path.Join(u.Path, suffix)
	s := u.String()
	return s
}
