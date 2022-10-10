//go:build darwin && cgo
// +build darwin,cgo

package cpu

import (
	"fmt"
	"unsafe"
)

// #include <mach/mach_host.h>
// #include <mach/host_info.h>
import "C"

// Get cpu statistics
func Get() (*Stats, error) {
	return collectCPUStats()
}

// Stats represents cpu statistics for darwin
type Stats struct {
	User, System, Idle, Nice, Total uint64
}

func collectCPUStats() (*Stats, error) {
	var cpuLoad C.host_cpu_load_info_data_t
	var count C.mach_msg_type_number_t = C.HOST_CPU_LOAD_INFO_COUNT
	ret := C.host_statistics(C.host_t(C.mach_host_self()), C.HOST_CPU_LOAD_INFO, C.host_info_t(unsafe.Pointer(&cpuLoad)), &count)
	if ret != C.KERN_SUCCESS {
		return nil, fmt.Errorf("host_statistics failed: %d", ret)
	}
	cpu := Stats{
		User:   uint64(cpuLoad.cpu_ticks[C.CPU_STATE_USER]),
		System: uint64(cpuLoad.cpu_ticks[C.CPU_STATE_SYSTEM]),
		Idle:   uint64(cpuLoad.cpu_ticks[C.CPU_STATE_IDLE]),
		Nice:   uint64(cpuLoad.cpu_ticks[C.CPU_STATE_NICE]),
	}
	cpu.Total = cpu.User + cpu.System + cpu.Idle + cpu.Nice
	return &cpu, nil
}
