package hybrid

import "time"

type memoryguard struct {
	Enabled  bool
	Interval time.Duration
	stop     chan bool
}

func (mg *memoryguard) Run(hm *HybridMap) {
	ticker := time.NewTicker(mg.Interval)
	for {
		select {
		case <-ticker.C:
			hm.TuneMemory()
		case <-mg.stop:
			ticker.Stop()
			return
		}
	}
}

func stopMemoryGuard(hm *HybridMap) {
	hm.memoryguard.stop <- true
}

func runMemoryGuard(c *HybridMap, ci time.Duration) {
	mg := &memoryguard{
		Interval: ci,
		stop:     make(chan bool),
	}
	c.memoryguard = mg
	go mg.Run(c)
}
