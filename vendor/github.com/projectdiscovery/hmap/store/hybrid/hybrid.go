package hybrid

import (
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/projectdiscovery/hmap/store/cache"
	"github.com/projectdiscovery/hmap/store/disk"
	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

type MapType int

const (
	Memory MapType = iota
	Disk
	Hybrid
)

type DBType int

const (
	LevelDB DBType = iota
	PogrebDB
	BBoltDB
	BuntDB
)

type Options struct {
	MemoryExpirationTime time.Duration
	DiskExpirationTime   time.Duration
	JanitorTime          time.Duration
	Type                 MapType
	DBType               DBType
	MemoryGuardForceDisk bool
	MemoryGuard          bool
	MaxMemorySize        int
	MemoryGuardTime      time.Duration
	Path                 string
	Cleanup              bool
	Name                 string
	// Remove temporary hmap in the temporary folder older than duration
	RemoveOlderThan time.Duration
}

var DefaultOptions = Options{
	Type:                 Memory,
	MemoryExpirationTime: time.Duration(5) * time.Minute,
	JanitorTime:          time.Duration(1) * time.Minute,
}

var DefaultMemoryOptions = Options{
	Type: Memory,
}

var DefaultDiskOptions = Options{
	Type:            Disk,
	DBType:          LevelDB,
	Cleanup:         true,
	RemoveOlderThan: 24 * time.Hour * 2, // at startup removes temporary dbs older than x days
}

var DefaultHybridOptions = Options{
	Type:                 Hybrid,
	DBType:               PogrebDB,
	MemoryExpirationTime: time.Duration(5) * time.Minute,
	JanitorTime:          time.Duration(1) * time.Minute,
}

type HybridMap struct {
	options     *Options
	memorymap   cache.Cache
	diskmap     disk.DB
	diskmapPath string
	memoryguard *memoryguard
}

func New(options Options) (*HybridMap, error) {
	executableName := fileutil.ExecutableName()

	// Due to potential system failures, the first operation is removing leftovers older than the defined duration
	// if cleanup is true and a max age duration has been defined
	if options.Cleanup && options.Path == "" && options.RemoveOlderThan > 0 {
		targetCleanupDir := os.TempDir()
		tmpFiles, err := os.ReadDir(targetCleanupDir)
		if err != nil {
			return nil, err
		}
		now := time.Now()
		for _, tmpFile := range tmpFiles {
			// discard non folders
			if !tmpFile.IsDir() {
				continue
			}
			// discard folders not containing the executable name
			if !stringsutil.ContainsAny(tmpFile.Name(), executableName) {
				continue
			}

			tmpFileInfo, err := tmpFile.Info()
			if err != nil {
				continue
			}
			modTime := tmpFileInfo.ModTime()
			if now.Sub(modTime) > options.RemoveOlderThan {
				targetFolderFullPath := filepath.Join(targetCleanupDir, tmpFileInfo.Name())
				os.RemoveAll(targetFolderFullPath)
			}
		}
	}

	var hm HybridMap
	if options.Type == Memory || options.Type == Hybrid {
		hm.memorymap = cache.New(options.MemoryExpirationTime, options.JanitorTime)
	}

	if options.Type == Disk || options.Type == Hybrid {
		diskmapPathm := options.Path
		if diskmapPathm == "" {
			var err error
			diskmapPathm, err = os.MkdirTemp("", executableName)
			if err != nil {
				return nil, err
			}
		}

		hm.diskmapPath = diskmapPathm
		switch options.DBType {
		case PogrebDB:
			if disk.OpenPogrebDB == nil {
				return nil, disk.ErrNotSupported
			}
			db, err := disk.OpenPogrebDB(diskmapPathm)
			if err != nil {
				return nil, err
			}
			hm.diskmap = db
		case BBoltDB:
			db, err := disk.OpenBoltDBB(filepath.Join(diskmapPathm, "bb"))
			if err != nil {
				return nil, err
			}
			db.BucketName = options.Name
			hm.diskmap = db
		case BuntDB:
			db, err := disk.OpenBuntDB(filepath.Join(diskmapPathm, "bunt"))
			if err != nil {
				return nil, err
			}
			hm.diskmap = db
		case LevelDB:
			fallthrough
		default:
			db, err := disk.OpenLevelDB(diskmapPathm)
			if err != nil {
				return nil, err
			}
			hm.diskmap = db
		}
	}

	if options.Type == Hybrid {
		hm.memorymap.OnEvicted(func(k string, v interface{}) {
			_ = hm.diskmap.Set(k, v.([]byte), 0)
		})
	}

	if options.MemoryGuard {
		runMemoryGuard(&hm, options.MemoryGuardTime)
		runtime.SetFinalizer(&hm, stopMemoryGuard)
	}

	hm.options = &options

	return &hm, nil
}

func (hm *HybridMap) Close() error {
	if hm.diskmap != (disk.DB)(nil) {
		hm.diskmap.Close()
	}
	if hm.diskmapPath != "" && hm.options.Cleanup {
		return os.RemoveAll(hm.diskmapPath)
	}
	return nil
}

func (hm *HybridMap) Set(k string, v []byte) error {
	var err error
	switch hm.options.Type {
	case Hybrid:
		fallthrough
	case Memory:
		if hm.options.MemoryGuardForceDisk {
			err = hm.diskmap.Set(k, v, hm.options.DiskExpirationTime)
		} else {
			hm.memorymap.Set(k, v)
		}
	case Disk:
		err = hm.diskmap.Set(k, v, hm.options.DiskExpirationTime)
	}

	return err
}

func (hm *HybridMap) Get(k string) ([]byte, bool) {
	switch hm.options.Type {
	case Memory:
		v, ok := hm.memorymap.Get(k)
		if ok {
			return v.([]byte), ok
		}
		return []byte{}, ok
	case Hybrid:
		v, ok := hm.memorymap.Get(k)
		if ok {
			return v.([]byte), ok
		}
		vm, err := hm.diskmap.Get(k)
		// load it in memory since it has been recently used
		if err == nil {
			hm.memorymap.Set(k, vm)
		}
		return vm, err == nil
	case Disk:
		v, err := hm.diskmap.Get(k)
		return v, err == nil
	}

	return []byte{}, false
}

func (hm *HybridMap) Del(key string) error {
	switch hm.options.Type {
	case Memory:
		hm.memorymap.Delete(key)
	case Hybrid:
		hm.memorymap.Delete(key)
		return hm.diskmap.Del(key)
	case Disk:
		return hm.diskmap.Del(key)
	}

	return nil
}

func (hm *HybridMap) Scan(f func([]byte, []byte) error) {
	switch hm.options.Type {
	case Memory:
		hm.memorymap.Scan(f)
	case Hybrid:
		hm.memorymap.Scan(f)
		_ = hm.diskmap.Scan(disk.ScannerOptions{Handler: f})
	case Disk:
		_ = hm.diskmap.Scan(disk.ScannerOptions{Handler: f})
	}
}

func (hm *HybridMap) Size() int64 {
	var count int64
	if hm.memorymap != nil {
		count += int64(hm.memorymap.ItemCount())
	}
	if hm.diskmap != (disk.DB)(nil) {
		count += hm.diskmap.Size()
	}
	return count
}

func (hm *HybridMap) TuneMemory() {
	// si := sysinfo.Get()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	if m.Alloc >= uint64(hm.options.MaxMemorySize) {
		hm.options.MemoryGuardForceDisk = true
	} else {
		hm.options.MemoryGuardForceDisk = false
	}
}
