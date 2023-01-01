// Inspired by https://github.com/natefinch/lumberjack

package writer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mholt/archiver"
	"github.com/projectdiscovery/gologger/levels"
	"gopkg.in/djherbis/times.v1"
)

func init() {
	// Set default dir to current directory + /logs
	if dir, err := os.Getwd(); err == nil {
		DefaultFileWithRotationOptions.Location = filepath.Join(dir, "logs")
	}

	DefaultFileWithRotationOptions.rotationcheck = time.Duration(10 * time.Second)

	// Current logfile name is "processname.log"
	DefaultFileWithRotationOptions.FileName = fmt.Sprintf("%s.log", filepath.Base(os.Args[0]))
	DefaultFileWithRotationOptions.BackupTimeFormat = "2006-01-02T15-04-05"
	DefaultFileWithRotationOptions.ArchiveFormat = "gz"
}

// FileWithRotation is a concurrent output writer to a file with rotation.
type FileWithRotation struct {
	options     *FileWithRotationOptions
	mutex       *sync.Mutex
	logFile     *os.File
	logfileTime time.Time
}

type FileWithRotationOptions struct {
	Location         string
	Rotate           bool
	rotationcheck    time.Duration
	RotationInterval time.Duration
	FileName         string
	Compress         bool
	MaxSize          int
	BackupTimeFormat string
	ArchiveFormat    string
	// Helpers
	RotateEachHour bool
	RotateEachDay  bool
}

var DefaultFileWithRotationOptions FileWithRotationOptions

// NewFileWithRotation returns a new file concurrent log writer.
func NewFileWithRotation(options *FileWithRotationOptions) (*FileWithRotation, error) {
	fwr := &FileWithRotation{
		options: options,
		mutex:   &sync.Mutex{},
	}
	// set log rotator monitor
	if fwr.options.Rotate {
		go scheduler(time.NewTicker(options.rotationcheck), fwr.checkAndRotate)
	}

	err := os.MkdirAll(fwr.options.Location, 0755)
	if err != nil {
		return nil, err
	}

	err = fwr.newLoggerSync()
	if err != nil {
		return nil, err
	}

	return fwr, nil
}

// Write writes an output to the underlying file
func (w *FileWithRotation) Write(data []byte, level levels.Level) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	switch level {
	case levels.LevelSilent:
		_, err := w.logFile.Write(data)
		if err != nil {
			return
		}

		_, err = w.logFile.Write([]byte("\n"))
		if err != nil {
			return
		}

	default:
		_, err := w.logFile.Write(data)
		if err != nil {
			return
		}
		_, err =w.logFile.Write([]byte("\n"))
		if err != nil {
			return
		}
	}
}

func (w *FileWithRotation) checkAndRotate() {
	timeNow := time.Now()
	// check size
	currentFileSizeMb, err := w.logFile.Stat()
	if err != nil {
		return
	}

	filesizeCheck := w.options.MaxSize > 0 && currentFileSizeMb.Size() >= int64(w.options.MaxSize*1024*1024)
	filechangedateCheck := w.options.RotationInterval > 0 && w.logfileTime.Add(w.options.RotationInterval).Before(timeNow)
	rotateEachHourCheck := w.options.RotateEachHour && w.logfileTime.Day() == timeNow.Day() && w.logfileTime.Hour() != timeNow.Hour()
	rotateEachDayCheck := w.options.RotateEachDay && w.logfileTime.Day() != timeNow.Day()

	// Rotate if:
	// - Size excedeed
	// - File max age excedeed
	// - RotateEachHour set and condition met
	// - RotateEachDay set and condition met
	if filesizeCheck || filechangedateCheck || rotateEachHourCheck || rotateEachDayCheck {
		w.mutex.Lock()
		w.Close()
		w.renameAndCompressLogs()
		_ =w.newLogger()
		w.mutex.Unlock()
	}
}

// Close and flushes the logger
func (w *FileWithRotation) Close() {
	_ = w.logFile.Sync()
	w.logFile.Close()
}

func (w *FileWithRotation) newLoggerSync() (err error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	return w.newLogger()
}

func (w *FileWithRotation) newLogger() (err error) {
	filename := filepath.Join(w.options.Location, w.options.FileName)
	logFile, err := w.CreateFile(filename)
	if err != nil {
		return err
	}
	w.logFile = logFile

	w.logfileTime, err = getChangeTime(filename)
	if err != nil {
		return err
	}

	return nil
}

func (w *FileWithRotation) CreateFile(filename string) (*os.File, error) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0755)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (w *FileWithRotation) renameAndCompressLogs() {
	// snapshot current filename log
	filename := filepath.Join(w.options.Location, w.options.FileName)
	fileExt := filepath.Ext(filename)
	filenameBase := strings.TrimSuffix(filename, fileExt)
	timeToSave := time.Now()
	if w.options.RotateEachHour {
		timeToSave = timeToSave.Truncate(1 * time.Hour)
	} else if w.options.RotateEachDay {
		timeToSave = timeToSave.Truncate(24 * time.Hour)
	}
	tmpFilename := filenameBase + "." + timeToSave.Format(w.options.BackupTimeFormat) + fileExt
	_ = os.Rename(filename, tmpFilename)

	if w.options.Compress {
		// start asyncronous compressing
		go func(filename string) {
			err := archiver.CompressFile(tmpFilename, filename+"."+w.options.ArchiveFormat)
			if err == nil {
				// remove the original file
				os.RemoveAll(tmpFilename)
			}
		}(tmpFilename)
	}
}

func scheduler(tick *time.Ticker, f func()) {
	for range tick.C {
		f()
	}
}


func getChangeTime(filename string) (time.Time, error) {
	timeNow := time.Now()
	t, err := times.Stat(filename)
	if err != nil {
		return timeNow, err
	}

	if t.HasChangeTime() {
		return t.ChangeTime(), nil
	}

	return timeNow, errors.New("No change time")
}

