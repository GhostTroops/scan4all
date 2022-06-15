package pogreb

import (
	"math"
	"time"

	"github.com/akrylysov/pogreb/fs"
)

// Options holds the optional DB parameters.
type Options struct {
	// BackgroundSyncInterval sets the amount of time between background Sync() calls.
	//
	// Setting the value to 0 disables the automatic background synchronization.
	// Setting the value to -1 makes the DB call Sync() after every write operation.
	BackgroundSyncInterval time.Duration

	// BackgroundCompactionInterval sets the amount of time between background Compact() calls.
	//
	// Setting the value to 0 disables the automatic background compaction.
	BackgroundCompactionInterval time.Duration

	// FileSystem sets the file system implementation.
	//
	// Default: fs.OSMMap.
	FileSystem fs.FileSystem

	maxSegmentSize             uint32
	compactionMinSegmentSize   uint32
	compactionMinFragmentation float32
}

func (src *Options) copyWithDefaults(path string) *Options {
	opts := Options{}
	if src != nil {
		opts = *src
	}
	if opts.FileSystem == nil {
		opts.FileSystem = fs.OSMMap
	}
	opts.FileSystem = fs.Sub(opts.FileSystem, path)
	if opts.maxSegmentSize == 0 {
		opts.maxSegmentSize = math.MaxUint32
	}
	if opts.compactionMinSegmentSize == 0 {
		opts.compactionMinSegmentSize = 32 << 20
	}
	if opts.compactionMinFragmentation == 0 {
		opts.compactionMinFragmentation = 0.5
	}
	return &opts
}
