package fileutil

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"debug/elf"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/asaskevich/govalidator"
	"github.com/mattn/go-isatty"
	"github.com/pkg/errors"
	osutils "github.com/projectdiscovery/utils/os"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"gopkg.in/yaml.v3"
)

// FileExists checks if the file exists in the provided path
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// FileExistsIn checks if the file exists in the allowed paths
func FileExistsIn(file string, allowedPaths ...string) (string, error) {
	fileAbsPath, err := filepath.Abs(file)
	if err != nil {
		return "", err
	}

	uniqAllowedPaths := sliceutil.Dedupe(allowedPaths)

	for _, allowedPath := range uniqAllowedPaths {
		allowedAbsPath, err := filepath.Abs(allowedPath)
		if err != nil {
			return "", err
		}
		// reject any path that for some reason was cleaned up and starts with .
		if stringsutil.HasPrefixAny(allowedAbsPath, ".") {
			return "", errors.New("invalid path")
		}

		allowedDirPath := allowedAbsPath
		if filepath.Ext(allowedAbsPath) != "" {
			allowedDirPath = filepath.Dir(allowedAbsPath)
		}
		if strings.HasPrefix(fileAbsPath, allowedDirPath) && FileExists(fileAbsPath) {
			return allowedDirPath, nil
		}
	}
	return "", errors.New("no allowed path found")
}

// FolderExists checks if the folder exists
func FolderExists(foldername string) bool {
	info, err := os.Stat(foldername)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		return false
	}
	return info.IsDir()
}

// FileOrFolderExists checks if the file/folder exists
func FileOrFolderExists(name string) bool {
	_, err := os.Stat(name)
	return !os.IsNotExist(err)
}

type FileFilters struct {
	OlderThan    time.Duration
	Prefix       string
	Suffix       string
	RegexPattern string
	CustomCheck  func(filename string) bool
	Callback     func(filename string) error
}

func DeleteFilesOlderThan(folder string, filter FileFilters) error {
	startScan := time.Now()
	return filepath.WalkDir(folder, func(osPathname string, de fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if osPathname == "" {
			return nil
		}
		if de.IsDir() {
			return nil
		}
		fileInfo, err := os.Stat(osPathname)
		if err != nil {
			return nil
		}
		fileName := fileInfo.Name()
		if filter.Prefix != "" && !strings.HasPrefix(fileName, filter.Prefix) {
			return nil
		}
		if filter.Suffix != "" && !strings.HasSuffix(fileName, filter.Suffix) {
			return nil
		}
		if filter.RegexPattern != "" {
			regex, err := regexp.Compile(filter.RegexPattern)
			if err != nil {
				return err
			}
			if !regex.MatchString(fileName) {
				return nil
			}
		}
		if filter.CustomCheck != nil && !filter.CustomCheck(osPathname) {
			return nil
		}
		if fileInfo.ModTime().Add(filter.OlderThan).Before(startScan) {
			if filter.Callback != nil {
				return filter.Callback(osPathname)
			} else {
				_ = os.RemoveAll(osPathname)
			}
		}
		return nil
	},
	)
}

// DownloadFile to specified path
func DownloadFile(filepath string, url string) error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
	}()
	_, err = io.Copy(out, resp.Body)
	return err
}

// CreateFolders in the list
func CreateFolders(paths ...string) error {
	for _, path := range paths {
		if err := CreateFolder(path); err != nil {
			return err
		}
	}

	return nil
}

// CreateFolder path
func CreateFolder(path string) error {
	return os.MkdirAll(path, 0700)
}

// HasStdin determines if the user has piped input
func HasStdin() bool {
	if osutils.IsWindows() && (isatty.IsTerminal(os.Stdin.Fd()) || isatty.IsCygwinTerminal(os.Stdin.Fd())) {
		return false
	}
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	mode := stat.Mode()

	isPipedFromChrDev := (mode & os.ModeCharDevice) == 0
	isPipedFromFIFO := (mode & os.ModeNamedPipe) != 0

	return isPipedFromChrDev || isPipedFromFIFO
}

// ReadFileWithReader streams r line by line on a channel.
//
// Deprecated: use LinesReader, which returns an iter.Seq2[string, error] and
// surfaces scanner errors. Equivalent invocation:
//
//	for line, err := range fileutil.LinesReader(r) { ... }
func ReadFileWithReader(r io.Reader) (chan string, error) {
	out := make(chan string)
	go func() {
		defer close(out)
		for line, err := range LinesReader(r) {
			if err != nil {
				return
			}
			out <- line
		}
	}()
	return out, nil
}

// ReadFileWithReaderAndBufferSize streams r line by line on a channel using
// the given scanner buffer size.
//
// Deprecated: use LinesReader with WithBufferSize. Equivalent invocation:
//
//	for line, err := range fileutil.LinesReader(r, fileutil.WithBufferSize(n)) { ... }
func ReadFileWithReaderAndBufferSize(r io.Reader, maxCapacity int) (chan string, error) {
	out := make(chan string)
	go func() {
		defer close(out)
		for line, err := range LinesReader(r, WithBufferSize(maxCapacity)) {
			if err != nil {
				return
			}
			out <- line
		}
	}()
	return out, nil
}

// ReadFile streams the file at filename line by line on a channel.
//
// Deprecated: use Lines, which returns an iter.Seq2[string, error] and
// surfaces open / scanner errors. Equivalent invocation:
//
//	for line, err := range fileutil.Lines(filename) { ... }
func ReadFile(filename string) (chan string, error) {
	if !FileExists(filename) {
		return nil, errors.New("file doesn't exist")
	}
	out := make(chan string)
	go func() {
		defer close(out)
		for line, err := range Lines(filename) {
			if err != nil {
				return
			}
			out <- line
		}
	}()
	return out, nil
}

// ReadFileWithBufferSize streams the file at filename line by line on a
// channel using the given scanner buffer size.
//
// Deprecated: use Lines with WithBufferSize. Equivalent invocation:
//
//	for line, err := range fileutil.Lines(filename, fileutil.WithBufferSize(n)) { ... }
func ReadFileWithBufferSize(filename string, maxCapacity int) (chan string, error) {
	if !FileExists(filename) {
		return nil, errors.New("file doesn't exist")
	}
	out := make(chan string)
	go func() {
		defer close(out)
		for line, err := range Lines(filename, WithBufferSize(maxCapacity)) {
			if err != nil {
				return
			}
			out <- line
		}
	}()
	return out, nil
}

// WithComment skips lines whose first non-whitespace characters are prefix,
// for both Lines and ReadLinesStream. An empty prefix leaves every line in
// place. The skipped line is not split or trimmed.
func WithComment(prefix string) LineOption {
	return func(c *lineConfig) { c.comment = prefix }
}

// ReadFileWithError reads a file and streams lines with proper error handling
// Returns two channels: one for lines and one for errors
func ReadFileWithError(filename string) (<-chan string, <-chan error, error) {
	if !FileExists(filename) {
		return nil, nil, errors.New("file doesn't exist")
	}

	linesCh := make(chan string)
	errCh := make(chan error, 1)

	go func() {
		defer close(linesCh)
		defer close(errCh)

		file, err := os.Open(filename)
		if err != nil {
			errCh <- err
			return
		}
		defer func() { _ = file.Close() }()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			linesCh <- scanner.Text()
		}

		if err := scanner.Err(); err != nil {
			errCh <- err
		}
	}()

	return linesCh, errCh, nil
}

// ReadLinesStream reads a file and streams lines with configurable options
// Supports trim, skip empty, comment filtering, and custom buffer size
func ReadLinesStream(filename string, opts ...LineOption) (<-chan string, <-chan error) {
	linesCh := make(chan string)
	errCh := make(chan error, 1)

	go func() {
		defer close(linesCh)
		defer close(errCh)

		file, err := os.Open(filename)
		if err != nil {
			errCh <- err
			return
		}
		defer func() { _ = file.Close() }()

		cfg := &lineConfig{}
		for _, opt := range opts {
			opt(cfg)
		}

		scanner := bufio.NewScanner(file)
		if cfg.bufferSize > 0 {
			scanner.Buffer(make([]byte, cfg.bufferSize), cfg.bufferSize)
		}

		for scanner.Scan() {
			line := scanner.Text()

			if isComment(line, cfg.comment) {
				continue
			}
			if cfg.trimSpace {
				line = strings.TrimSpace(line)
			}
			if cfg.skipEmpty && line == "" {
				continue
			}

			linesCh <- line
		}

		if err := scanner.Err(); err != nil {
			errCh <- err
		}
	}()

	return linesCh, errCh
}

// GetTempFileName generate a temporary file name
func GetTempFileName() (string, error) {
	tmpfile, err := os.CreateTemp("", "")
	if err != nil {
		return "", err
	}
	tmpFileName := tmpfile.Name()
	if err := tmpfile.Close(); err != nil {
		return tmpFileName, err
	}
	err = os.RemoveAll(tmpFileName)
	return tmpFileName, err
}

// CopyFile from source to destination
func CopyFile(src, dst string) error {
	if !FileExists(src) {
		return errors.New("source file doesn't exist")
	}
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() {
		_ = srcFile.Close()
	}()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		_ = dstFile.Close()
	}()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	return dstFile.Sync()
}

type EncodeType uint8

const (
	YAML EncodeType = iota
	JSON
)

func Unmarshal(encodeType EncodeType, data []byte, obj interface{}) error {
	switch {
	case FileExists(string(data)):
		dataFile, err := os.Open(string(data))
		if err != nil {
			return err
		}
		defer func() {
			_ = dataFile.Close()
		}()
		return UnmarshalFromReader(encodeType, dataFile, obj)
	default:
		return UnmarshalFromReader(encodeType, bytes.NewReader(data), obj)
	}
}

func UnmarshalFromReader(encodeType EncodeType, r io.Reader, obj interface{}) error {
	switch encodeType {
	case YAML:
		return yaml.NewDecoder(r).Decode(obj)
	case JSON:
		return json.NewDecoder(r).Decode(obj)
	default:
		return errors.New("unsopported encode type")
	}
}

func Marshal(encodeType EncodeType, data []byte, obj interface{}) error {
	isFilePath, _ := govalidator.IsFilePath(string(data))
	switch {
	case isFilePath:
		dataFile, err := os.Create(string(data))
		if err != nil {
			return err
		}
		defer func() {
			_ = dataFile.Close()
		}()
		return MarshalToWriter(encodeType, dataFile, obj)
	default:
		return MarshalToWriter(encodeType, bytes.NewBuffer(data), obj)
	}
}

func MarshalToWriter(encodeType EncodeType, r io.Writer, obj interface{}) error {
	switch encodeType {
	case YAML:
		return yaml.NewEncoder(r).Encode(obj)
	case JSON:
		return json.NewEncoder(r).Encode(obj)
	default:
		return errors.New("unsopported encode type")
	}
}

func ExecutableName() string {
	executablePath, err := os.Executable()
	if err == nil {
		executablePath = os.Args[0]
	}
	executableNameWithExt := filepath.Base(executablePath)
	return stringsutil.TrimSuffixAny(executableNameWithExt, filepath.Ext(executableNameWithExt))
}

// RemoveAll specified paths, returning those that caused error
func RemoveAll(paths ...string) (errored map[string]error) {
	errored = make(map[string]error)
	for _, path := range paths {
		if err := os.RemoveAll(path); err != nil {
			errored[path] = err
		}
	}
	return
}

// UseMusl checks if the specified elf file uses musl
func UseMusl(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = file.Close()
	}()
	elfFile, err := elf.NewFile(file)
	if err != nil {
		return false, err
	}
	importedLibraries, err := elfFile.ImportedLibraries()
	if err != nil {
		return false, err
	}
	for _, importedLibrary := range importedLibraries {
		if stringsutil.ContainsAny(importedLibrary, "libc.musl-") {
			return true, nil
		}
	}
	return false, nil
}

// IsReadable verify file readability
func IsReadable(fileName string) (bool, error) {
	return HasPermission(fileName, os.O_RDONLY)
}

// IsWriteable verify file writeability
func IsWriteable(fileName string) (bool, error) {
	return HasPermission(fileName, os.O_WRONLY)
}

// HasPermission checks if the file has the requested permission
func HasPermission(fileName string, permission int) (bool, error) {
	file, err := os.OpenFile(fileName, permission, 0666)
	if err != nil {
		if os.IsPermission(err) {
			return false, errors.Wrap(err, "permission error")
		}
		return false, err
	}
	_ = file.Close()

	return true, nil
}

var ErrInvalidSeparator = errors.New("invalid separator")

var SkipEmptyLine = func(line []byte) bool {
	return len(line) > 0
}

// CountLines counts the lines in a file
func CountLines(filename string) (uint, error) {
	return CountLinesWithSeparator([]byte("\n"), filename)
}

// CountLinesWithSeparator of a file
func CountLinesWithSeparator(separator []byte, filename string) (uint, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}

	defer func() {
		_ = file.Close()
	}()
	if len(separator) == 0 {
		return 0, ErrInvalidSeparator
	}

	return CountLinesWithOptions(file, separator, nil)
}

// IsNotEmpty determines if a data chunk is empty
var IsNotEmpty = func(data []byte) bool {
	return len(data) > 0
}

// CountLinesWithOptions from a reader and custom filter function
func CountLinesWithOptions(reader io.Reader, separator []byte, filter func([]byte) bool) (uint, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		dataLen := len(data)
		if atEOF && dataLen == 0 {
			return 0, nil, nil
		}
		if i := bytes.Index(data, separator); i >= 0 {
			return i + len(separator), data[0:i], nil
		}
		if atEOF {
			return dataLen, data, nil
		}
		return 0, nil, nil
	})

	var count uint
	for scanner.Scan() {
		if filter == nil || filter(scanner.Bytes()) {
			count++
		}
	}
	return count, scanner.Err()
}

// SubstituteConfigFromEnvVars reads a config file and generates a reader with substituted config values from environment variables
func SubstituteConfigFromEnvVars(filepath string) (io.Reader, error) {
	var config strings.Builder

	lines, err := ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	for line := range lines {
		config.WriteString(substituteEnvVars(string(line)))
		config.WriteString("\n")
	}

	return strings.NewReader(config.String()), nil
}

// substituteEnvVars identifies environment variables declared inline and tries to replace them using os.Getenv
func substituteEnvVars(line string) string {
	for _, word := range strings.Fields(line) {
		word = strings.Trim(word, `"`)
		if strings.HasPrefix(word, "$") {
			key := strings.TrimPrefix(word, "$")
			substituteEnv := os.Getenv(key)
			if substituteEnv != "" {
				line = strings.Replace(line, word, substituteEnv, 1)
			}
		}
	}
	return line
}

// FileSizeToByteLen converts a file size with units(kb, mb, gb, tb) to byte length
// e.g. 1kb -> 1024
// If no unit is provided, it will fallback to mb. e.g: '2' will be converted to 2097152.
func FileSizeToByteLen(fileSize string) (int, error) {
	fileSize = strings.ToLower(fileSize)
	// default to mb
	if size, err := strconv.Atoi(fileSize); err == nil {
		return size * 1024 * 1024, nil
	}
	if len(fileSize) < 3 {
		return 0, errors.New("invalid size value")
	}
	sizeUnit := fileSize[len(fileSize)-2:]
	size, err := strconv.Atoi(fileSize[:len(fileSize)-2])
	if err != nil {
		return 0, errors.New("parse error: " + err.Error())
	}
	if size < 0 {
		return 0, errors.New("size cannot be negative")
	}
	if strings.EqualFold(sizeUnit, "kb") {
		return size * 1024, nil
	} else if strings.EqualFold(sizeUnit, "mb") {
		return size * 1024 * 1024, nil
	} else if strings.EqualFold(sizeUnit, "gb") {
		return size * 1024 * 1024 * 1024, nil
	} else if strings.EqualFold(sizeUnit, "tb") {
		return size * 1024 * 1024 * 1024 * 1024, nil
	}
	return 0, errors.New("unsupported size unit")
}

// OpenOrCreate opens the named file for reading. If successful, methods on
// the returned file can be used for reading; the associated file
// descriptor has mode O_RDWR.
// If there is an error, it'll create the named file with mode 0666.
// If successful, methods on the returned File can be used for I/O;
// the associated file descriptor has mode O_RDWR.
// If there is an error, it will be of type *PathError.
// Note: The file gets created only if the target directory exists
func OpenOrCreateFile(name string) (*os.File, error) {
	if FileExists(name) {
		return os.OpenFile(name, os.O_RDWR, 0666)
	}
	return os.OpenFile(name, os.O_RDWR|os.O_CREATE, 0666)
}

// DedupeLines reads a file and removes duplicate lines from it.
// The function can be memory intensive for large files.
func DedupeLines(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return errors.Wrapf(err, "could not open file: %s", filename)
	}
	defer func() {
		_ = file.Close()
	}()

	seenLines := make(map[string]struct{})
	var deduplicatedLines []string

	info, err := file.Stat()
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(file)
	maxSize := int(info.Size())
	buffer := make([]byte, 0, maxSize)
	scanner.Buffer(buffer, maxSize)
	for scanner.Scan() {
		line := scanner.Text()
		if _, exists := seenLines[line]; !exists {
			seenLines[line] = struct{}{}
			deduplicatedLines = append(deduplicatedLines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return errors.Wrapf(err, "could not read file: %s", filename)
	}

	return os.WriteFile(filename, []byte(strings.Join(deduplicatedLines, "\n")+"\n"), 0644)
}

// IsEmpty checks if the file is empty
func IsEmpty(filename string) (bool, error) {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return false, err
	}

	if fileInfo.Size() == 0 {
		return true, nil
	}

	file, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = file.Close()
	}()

	// Read up to 512 bytes to check for non-space characters
	buffer := make([]byte, 16)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return false, err
	}

	// Check if all read characters are spaces, null characters, new lines, or carriage returns
	for i := 0; i < n; i++ {
		if !unicode.IsSpace(rune(buffer[i])) && buffer[i] != 0 && buffer[i] != '\n' && buffer[i] != '\r' {
			return false, nil
		}
	}
	return true, nil
}
