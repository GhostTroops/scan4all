// Copyright 2012 The LevelDB-Go and Pebble Authors. All rights reserved. Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package pebble

import (
	"fmt"

	"github.com/cockroachdb/pebble/internal/base"
	"github.com/cockroachdb/pebble/vfs"
)

type fileType = base.FileType

// FileNum is an identifier for a file within a database.
type FileNum = base.FileNum

const (
	fileTypeLog      = base.FileTypeLog
	fileTypeLock     = base.FileTypeLock
	fileTypeTable    = base.FileTypeTable
	fileTypeManifest = base.FileTypeManifest
	fileTypeCurrent  = base.FileTypeCurrent
	fileTypeOptions  = base.FileTypeOptions
	fileTypeTemp     = base.FileTypeTemp
)

func setCurrentFile(dirname string, fs vfs.FS, fileNum FileNum) error {
	newFilename := base.MakeFilename(fs, dirname, fileTypeCurrent, fileNum)
	oldFilename := base.MakeFilename(fs, dirname, fileTypeTemp, fileNum)
	fs.Remove(oldFilename)
	f, err := fs.Create(oldFilename)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "MANIFEST-%s\n", fileNum); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return fs.Rename(oldFilename, newFilename)
}
