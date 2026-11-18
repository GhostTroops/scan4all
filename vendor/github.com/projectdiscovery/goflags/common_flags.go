package goflags

import (
	"time"

	"github.com/projectdiscovery/utils/process"
)

// CommonFlags contains common flags shared across ProjectDiscovery tools.
// These flags provide consistent behavior across all tools in the ecosystem.
type CommonFlags struct {
	// MaxTime is the maximum duration for the entire execution.
	// When this duration is reached, an interrupt signal is sent to trigger graceful termination.
	// Example values: "1h", "30m", "1h30m", "2h45m30s"
	MaxTime time.Duration

	handlersStarted bool
	maxTimeTimer    *time.Timer
	activeMaxTime   time.Duration
}

// AddCommonFlags registers common flags to the flagset and returns a CommonFlags struct.
// The handlers are automatically started when Parse returns and refreshed
// after a successful MergeConfigFile call.
//
// Usage:
//
//	flagSet := goflags.NewFlagSet()
//	flagSet.AddCommonFlags()
//	flagSet.Parse()
func (flagSet *FlagSet) AddCommonFlags() *CommonFlags {
	cf := &CommonFlags{}

	flagSet.CreateGroup("common", "Common",
		flagSet.DurationVarP(&cf.MaxTime, "max-time", "mt", 0, "maximum time to run before automatic termination (e.g., 1h, 30m)"),
	)

	flagSet.commonFlags = cf
	return cf
}

// startCommonFlagsHandlers is called by Parse() to start handlers.
func (flagSet *FlagSet) startCommonFlagsHandlers() {
	if flagSet.commonFlags == nil {
		return
	}

	flagSet.commonFlags.handlersStarted = true
	flagSet.refreshCommonFlagsHandlers()
}

func (flagSet *FlagSet) refreshCommonFlagsHandlers() {
	if flagSet.commonFlags == nil || !flagSet.commonFlags.handlersStarted {
		return
	}

	flagSet.commonFlags.startMaxTimeHandler()
}

// startMaxTimeHandler replaces the active timer when MaxTime changes.
func (cf *CommonFlags) startMaxTimeHandler() {
	maxTime := cf.MaxTime
	if cf.maxTimeTimer != nil && cf.activeMaxTime == maxTime {
		return
	}

	if cf.maxTimeTimer != nil {
		cf.maxTimeTimer.Stop()
		cf.maxTimeTimer = nil
	}
	cf.activeMaxTime = maxTime

	if maxTime > 0 {
		cf.maxTimeTimer = time.AfterFunc(maxTime, process.SendInterrupt)
	}
}
