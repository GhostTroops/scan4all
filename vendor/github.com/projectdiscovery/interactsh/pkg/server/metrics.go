package server

import (
	"runtime"

	units "github.com/docker/go-units"
	"github.com/mackerelio/go-osstat/cpu"
	"github.com/mackerelio/go-osstat/network"
	"github.com/projectdiscovery/interactsh/pkg/storage"
)

type Metrics struct {
	Dns      uint64                `json:"dns"`
	Ftp      uint64                `json:"ftp"`
	Http     uint64                `json:"http"`
	Ldap     uint64                `json:"ldap"`
	Smb      uint64                `json:"smb"`
	Smtp     uint64                `json:"smtp"`
	Sessions int64                 `json:"sessions"`
	Cache    *storage.CacheMetrics `json:"cache"`
	Memory   *MemoryMetrics        `json:"memory"`
	Cpu      *CpuStats             `json:"cpu"`
	Network  *NetworkStats         `json:"network"`
}

func GetCacheMetrics(options *Options) *storage.CacheMetrics {
	cacheMetrics, _ := options.Storage.GetCacheMetrics()
	return cacheMetrics
}

type MemoryMetrics struct {
	Alloc        string `json:"alloc"`
	TotalAlloc   string `json:"total_alloc"`
	Sys          string `json:"sys"`
	Lookups      uint64 `json:"lookups"`
	Mallocs      uint64 `json:"mallocs"`
	Frees        uint64 `json:"frees"`
	HeapAlloc    string `json:"heap_allo"`
	HeapSys      string `json:"heap_sys"`
	HeapIdle     string `json:"head_idle"`
	HeapInuse    string `json:"heap_in_use"`
	HeapReleased string `json:"heap_released"`
	HeapObjects  uint64 `json:"heap_objects"`
	StackInuse   string `json:"stack_in_use"`
	StackSys     string `json:"stack_sys"`
	MSpanInuse   string `json:"mspan_in_use"`
	MSpanSys     string `json:"mspan_sys"`
	MCacheInuse  string `json:"mcache_in_use"`
	MCacheSys    string `json:"mcache_sys"`
}

func GetMemoryMetrics() *MemoryMetrics {
	var mStats runtime.MemStats
	runtime.ReadMemStats(&mStats)
	return &MemoryMetrics{
		Alloc:        units.HumanSize(float64(mStats.Alloc)),
		TotalAlloc:   units.HumanSize(float64(mStats.TotalAlloc)),
		Sys:          units.HumanSize(float64(mStats.Sys)),
		Lookups:      mStats.Lookups,
		Mallocs:      mStats.Mallocs,
		Frees:        mStats.Frees,
		HeapAlloc:    units.HumanSize(float64(mStats.HeapAlloc)),
		HeapSys:      units.HumanSize(float64(mStats.HeapSys)),
		HeapIdle:     units.HumanSize(float64(mStats.HeapIdle)),
		HeapInuse:    units.HumanSize(float64(mStats.HeapInuse)),
		HeapReleased: units.HumanSize(float64(mStats.HeapReleased)),
		HeapObjects:  mStats.HeapObjects,
		StackInuse:   units.HumanSize(float64(mStats.StackInuse)),
		StackSys:     units.HumanSize(float64(mStats.StackSys)),
		MSpanInuse:   units.HumanSize(float64(mStats.MSpanInuse)),
		MSpanSys:     units.HumanSize(float64(mStats.MSpanSys)),
		MCacheInuse:  units.HumanSize(float64(mStats.MCacheInuse)),
		MCacheSys:    units.HumanSize(float64(mStats.MCacheSys)),
	}
}

type CpuStats struct {
	User   uint64 `json:"user"`
	System uint64 `json:"system"`
	Idle   uint64 `json:"idle"`
	Nice   uint64 `json:"nice"`
	Total  uint64 `json:"total"`
}

func GetCpuMetrics() (cpuStats *CpuStats) {
	if cs, err := cpu.Get(); err == nil {
		cpuStats = &CpuStats{
			User:   cs.User,
			System: cs.System,
			Idle:   cs.Idle,
			Nice:   cs.Nice,
			Total:  cs.Total,
		}
	}
	return
}

type NetworkStats struct {
	Rx      string `json:"received"`
	rxBytes uint64
	Tx      string `json:"transmitted"`
	txBytes uint64
}

func GetNetworkMetrics() *NetworkStats {
	networkStats := &NetworkStats{}
	if nss, err := network.Get(); err == nil {
		for _, ns := range nss {
			networkStats.rxBytes += ns.RxBytes
			networkStats.txBytes += ns.TxBytes
		}
	}
	networkStats.Rx = units.HumanSize(float64(networkStats.rxBytes))
	networkStats.Tx = units.HumanSize(float64(networkStats.txBytes))
	return networkStats
}
