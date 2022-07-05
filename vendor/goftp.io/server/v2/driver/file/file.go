// Copyright 2020 The goftp Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package file

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"goftp.io/server/v2"
)

// Driver implements Driver directly read local file system
type Driver struct {
	RootPath string
}

// NewDriver implements Driver
func NewDriver(rootPath string) (server.Driver, error) {
	var err error
	rootPath, err = filepath.Abs(rootPath)
	if err != nil {
		return nil, err
	}
	return &Driver{rootPath}, nil
}

func (driver *Driver) realPath(path string) string {
	paths := strings.Split(path, "/")
	return filepath.Join(append([]string{driver.RootPath}, paths...)...)
}

// Stat implements Driver
func (driver *Driver) Stat(ctx *server.Context, path string) (os.FileInfo, error) {
	basepath := driver.realPath(path)
	rPath, err := filepath.Abs(basepath)
	if err != nil {
		return nil, err
	}
	return os.Lstat(rPath)
}

// ListDir implements Driver
func (driver *Driver) ListDir(ctx *server.Context, path string, callback func(os.FileInfo) error) error {
	basepath := driver.realPath(path)
	return filepath.Walk(basepath, func(f string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rPath, _ := filepath.Rel(basepath, f)
		if rPath == info.Name() {
			err = callback(info)
			if err != nil {
				return err
			}
			if info.IsDir() {
				return filepath.SkipDir
			}
		}
		return nil
	})
}

// DeleteDir implements Driver
func (driver *Driver) DeleteDir(ctx *server.Context, path string) error {
	rPath := driver.realPath(path)
	f, err := os.Lstat(rPath)
	if err != nil {
		return err
	}
	if f.IsDir() {
		return os.RemoveAll(rPath)
	}
	return errors.New("Not a directory")
}

// DeleteFile implements Driver
func (driver *Driver) DeleteFile(ctx *server.Context, path string) error {
	rPath := driver.realPath(path)
	f, err := os.Lstat(rPath)
	if err != nil {
		return err
	}
	if !f.IsDir() {
		return os.Remove(rPath)
	}
	return errors.New("Not a file")
}

// Rename implements Driver
func (driver *Driver) Rename(ctx *server.Context, fromPath string, toPath string) error {
	oldPath := driver.realPath(fromPath)
	newPath := driver.realPath(toPath)
	return os.Rename(oldPath, newPath)
}

// MakeDir implements Driver
func (driver *Driver) MakeDir(ctx *server.Context, path string) error {
	rPath := driver.realPath(path)
	return os.MkdirAll(rPath, os.ModePerm)
}

// GetFile implements Driver
func (driver *Driver) GetFile(ctx *server.Context, path string, offset int64) (int64, io.ReadCloser, error) {
	rPath := driver.realPath(path)
	f, err := os.Open(rPath)
	if err != nil {
		return 0, nil, err
	}
	defer func() {
		if err != nil && f != nil {
			f.Close()
		}
	}()

	info, err := f.Stat()
	if err != nil {
		return 0, nil, err
	}

	_, err = f.Seek(offset, io.SeekStart)
	if err != nil {
		return 0, nil, err
	}

	return info.Size() - offset, f, nil
}

// PutFile implements Driver
func (driver *Driver) PutFile(ctx *server.Context, destPath string, data io.Reader, offset int64) (int64, error) {
	rPath := driver.realPath(destPath)
	var isExist bool
	f, err := os.Lstat(rPath)
	if err == nil {
		isExist = true
		if f.IsDir() {
			return 0, errors.New("A dir has the same name")
		}
	} else {
		if os.IsNotExist(err) {
			isExist = false
		} else {
			return 0, errors.New(fmt.Sprintln("Put File error:", err))
		}
	}

	if offset > -1 && !isExist {
		offset = -1
	}

	if offset == -1 {
		if isExist {
			err = os.Remove(rPath)
			if err != nil {
				return 0, err
			}
		}
		f, err := os.Create(rPath)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		bytes, err := io.Copy(f, data)
		if err != nil {
			return 0, err
		}
		return bytes, nil
	}

	of, err := os.OpenFile(rPath, os.O_APPEND|os.O_RDWR, 0660)
	if err != nil {
		return 0, err
	}
	defer of.Close()

	info, err := of.Stat()
	if err != nil {
		return 0, err
	}
	if offset > info.Size() {
		return 0, fmt.Errorf("Offset %d is beyond file size %d", offset, info.Size())
	}

	_, err = of.Seek(offset, os.SEEK_END)
	if err != nil {
		return 0, err
	}

	bytes, err := io.Copy(of, data)
	if err != nil {
		return 0, err
	}

	return bytes, nil
}
