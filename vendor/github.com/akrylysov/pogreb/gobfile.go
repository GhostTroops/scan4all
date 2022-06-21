package pogreb

import (
	"encoding/gob"

	"github.com/akrylysov/pogreb/fs"
)

func readGobFile(fsys fs.FileSystem, name string, v interface{}) error {
	f, err := openFile(fsys, name, false)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := gob.NewDecoder(f)
	return dec.Decode(v)
}

func writeGobFile(fsys fs.FileSystem, name string, v interface{}) error {
	f, err := openFile(fsys, name, true)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := gob.NewEncoder(f)
	return enc.Encode(v)
}
