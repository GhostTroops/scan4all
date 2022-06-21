package filekv

import (
	"bufio"
	"io"
	"os"
)

func (f *FileDB) Merge(items ...interface{}) (uint, error) {
	defer f.tmpDb.Sync()
	var count uint
	for _, item := range items {
		switch itemData := item.(type) {
		case []string:
			for _, data := range itemData {
				f.tmpDb.WriteString(data + "\n")
				count++
				f.stats.NumberOfAddedItems++
			}
		case io.Reader:
			c, err := f.MergeReader(itemData)
			if err != nil {
				return 0, err
			}
			count += c
		case string:
			c, err := f.MergeFile(itemData)
			if err != nil {
				return 0, err
			}
			count += c
		}
	}
	return count, nil
}

func (f *FileDB) MergeFile(filename string) (uint, error) {
	defer f.tmpDb.Sync()
	newF, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer newF.Close()
	return f.MergeReader(newF)
}

func (f *FileDB) MergeReader(reader io.Reader) (uint, error) {
	defer f.tmpDb.Sync()
	maxCapacity := 512 * 1024 * 1024
	var count uint
	sc := bufio.NewScanner(reader)
	buf := make([]byte, maxCapacity)
	sc.Buffer(buf, maxCapacity)
	for sc.Scan() {
		f.tmpDb.WriteString(sc.Text() + "\n")
		count++
		f.stats.NumberOfAddedItems++
	}
	return count, nil
}
