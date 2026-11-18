package metafiles

import (
	"runtime"
	"sync"

	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/utils/env"
)

type StorageType int

const (
	InMemory StorageType = iota
	Hybrid
)

var (
	MaxHostsEntires = 4096
	// LoadAllEntries is a switch when true loads all entries to hybrid storage
	// backend and uses it even if in-memory storage backend was requested
	LoadAllEntries = false
)

func init() {
	MaxHostsEntires = env.GetEnvOrDefault("HF_MAX_HOSTS", 4096)
	LoadAllEntries = env.GetEnvOrDefault("HF_LOAD_ALL", false)
}

// GetHostsFileDnsData returns the immutable dns data that is constant throughout the program
// lifecycle and shouldn't be purged by cache etc.
func GetHostsFileDnsData(storage StorageType) (*hybrid.HybridMap, error) {
	if LoadAllEntries {
		storage = Hybrid
	}
	switch storage {
	case InMemory:
		return getHFInMemory()
	case Hybrid:
		return getHFHybridStorage()
	}
	return getHFInMemory()
}

// == initialize in-memory hostmap on demand
var (
	hmMem       *hybrid.HybridMap
	hmErr       error
	hostMemInit = sync.OnceFunc(func() {
		opts := hybrid.DefaultMemoryOptions
		hmMem, hmErr = hybrid.New(opts)
		if hmErr != nil {
			return
		}
		hmErr = loadHostsFile(hmMem, MaxHostsEntires)
		if hmErr != nil {
			_ = hmMem.Close()
			return
		}
	})
)

// getImm
func getHFInMemory() (*hybrid.HybridMap, error) {
	hostMemInit()
	return hmMem, hmErr
}

// == initialize hybrid hostmap on demand
var (
	hmHybrid  *hybrid.HybridMap
	hmHybErr  error
	hmHybInit = sync.OnceFunc(func() {
		opts := hybrid.DefaultHybridOptions
		opts.Cleanup = true
		hmHybrid, hmHybErr = hybrid.New(opts)
		if hmHybErr != nil {
			return
		}
		hmHybErr = loadHostsFile(hmHybrid, -1)
		if hmHybErr != nil {
			_ = hmHybrid.Close()
			return
		}
		// set finalizer for cleanup
		runtime.SetFinalizer(hmHybrid, func(hm *hybrid.HybridMap) {
			_ = hm.Close()
		})
	})
)

func getHFHybridStorage() (*hybrid.HybridMap, error) {
	hmHybInit()
	return hmHybrid, hmHybErr
}
