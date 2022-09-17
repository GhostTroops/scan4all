// Copyright 2019 The LevelDB-Go and Pebble Authors. All rights reserved. Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package pebble

import (
	"time"

	"github.com/cockroachdb/errors"
	"github.com/cockroachdb/pebble/internal/rate"
)

var nilPacer = &noopPacer{}

type limiter interface {
	DelayN(now time.Time, n int) time.Duration
	AllowN(now time.Time, n int) bool
	Burst() int
}

// pacer is the interface for flush and compaction rate limiters. The rate limiter
// is possible applied on each iteration step of a flush or compaction. This is to
// limit background IO usage so that it does not contend with foreground traffic.
type pacer interface {
	maybeThrottle(bytesIterated uint64) error
}

// compactionInternalPacer contains fields and methods common to compactionPacer
// and flushPacer.
type compactionInternalPacer struct {
	limiter limiter

	iterCount             uint64
	prevBytesIterated     uint64
	refreshBytesThreshold uint64
	slowdownThreshold     uint64
}

// limit applies rate limiting if the current byte level is below the configured
// threshold.
func (p *compactionInternalPacer) limit(amount, currentLevel uint64) error {
	if currentLevel <= p.slowdownThreshold {
		burst := p.limiter.Burst()
		for amount > uint64(burst) {
			d := p.limiter.DelayN(time.Now(), burst)
			if d == rate.InfDuration {
				return errors.Errorf("pacing failed")
			}
			time.Sleep(d)
			amount -= uint64(burst)
		}
		d := p.limiter.DelayN(time.Now(), int(amount))
		if d == rate.InfDuration {
			return errors.Errorf("pacing failed")
		}
		time.Sleep(d)
	} else {
		burst := p.limiter.Burst()
		for amount > uint64(burst) {
			p.limiter.AllowN(time.Now(), burst)
			amount -= uint64(burst)
		}
		p.limiter.AllowN(time.Now(), int(amount))
	}
	return nil
}

// compactionPacerInfo contains information necessary for compaction pacing.
type compactionPacerInfo struct {
	// slowdownThreshold is the low watermark for compaction debt. If compaction debt is
	// below this threshold, we slow down compactions. If compaction debt is above this
	// threshold, we let compactions continue as fast as possible. We want to keep
	// compaction speed as slow as possible to match the speed of flushes. This threshold
	// is set so that a single flush cannot contribute enough compaction debt to overshoot
	// the threshold.
	slowdownThreshold   uint64
	totalCompactionDebt uint64
	// totalDirtyBytes is the number of dirty bytes in memtables. The compaction
	// pacer can monitor changes to this value to determine if user writes have
	// stopped.
	totalDirtyBytes uint64
}

// compactionPacerEnv defines the environment in which the compaction rate limiter
// is applied.
type compactionPacerEnv struct {
	limiter      limiter
	memTableSize uint64

	getInfo func() compactionPacerInfo
}

// compactionPacer rate limits compactions depending on compaction debt. The rate
// limiter is applied at a rate that keeps compaction debt at a steady level. If
// compaction debt increases at a rate that is faster than the system can handle,
// no rate limit is applied.
type compactionPacer struct {
	compactionInternalPacer
	env                 compactionPacerEnv
	totalCompactionDebt uint64
	totalDirtyBytes     uint64
}

func newCompactionPacer(env compactionPacerEnv) *compactionPacer {
	return &compactionPacer{
		env: env,
		compactionInternalPacer: compactionInternalPacer{
			limiter: env.limiter,
		},
	}
}

// maybeThrottle slows down compactions to match memtable flush rate. The DB
// provides a compaction debt estimate and a slowdown threshold. We subtract the
// compaction debt estimate by the bytes iterated in the current compaction. If
// the new compaction debt estimate is below the threshold, the rate limiter is
// applied. If the new compaction debt is above the threshold, the rate limiter
// is not applied.
func (p *compactionPacer) maybeThrottle(bytesIterated uint64) error {
	if bytesIterated == 0 {
		return nil
	}

	// Recalculate total compaction debt and the slowdown threshold only once
	// every 1000 iterations or when the refresh threshold is hit since it
	// requires grabbing DB.mu which is expensive.
	if p.iterCount == 0 || bytesIterated > p.refreshBytesThreshold {
		pacerInfo := p.env.getInfo()
		p.slowdownThreshold = pacerInfo.slowdownThreshold
		p.totalCompactionDebt = pacerInfo.totalCompactionDebt
		p.refreshBytesThreshold = bytesIterated + (p.env.memTableSize * 5 / 100)
		p.iterCount = 1000
		if p.totalDirtyBytes == pacerInfo.totalDirtyBytes {
			// The total dirty bytes in the memtables have not changed since the
			// previous call: user writes have completely stopped. Allow the
			// compaction to proceed as fast as possible until the next
			// recalculation. We adjust the recalculation threshold so that we can be
			// nimble in the face of new user writes.
			p.totalCompactionDebt += p.slowdownThreshold
			p.iterCount = 100
		}
		p.totalDirtyBytes = pacerInfo.totalDirtyBytes
	}
	p.iterCount--

	var curCompactionDebt uint64
	if p.totalCompactionDebt > bytesIterated {
		curCompactionDebt = p.totalCompactionDebt - bytesIterated
	}

	compactAmount := bytesIterated - p.prevBytesIterated
	p.prevBytesIterated = bytesIterated

	// We slow down compactions when the compaction debt falls below the slowdown
	// threshold, which is set dynamically based on the number of non-empty levels.
	// This will only occur if compactions can keep up with the pace of flushes. If
	// bytes are flushed faster than how fast compactions can occur, compactions
	// proceed at maximum (unthrottled) speed.
	return p.limit(compactAmount, curCompactionDebt)
}

// flushPacerInfo contains information necessary for compaction pacing.
type flushPacerInfo struct {
	inuseBytes uint64
}

// flushPacerEnv defines the environment in which the compaction rate limiter is
// applied.
type flushPacerEnv struct {
	limiter      limiter
	memTableSize uint64

	getInfo func() flushPacerInfo
}

// flushPacer rate limits memtable flushing to match the speed of incoming user
// writes. If user writes come in faster than the memtable can be flushed, no
// rate limit is applied.
type flushPacer struct {
	compactionInternalPacer
	env                flushPacerEnv
	inuseBytes         uint64
	adjustedInuseBytes uint64
}

func newFlushPacer(env flushPacerEnv) *flushPacer {
	return &flushPacer{
		env: env,
		compactionInternalPacer: compactionInternalPacer{
			limiter:           env.limiter,
			slowdownThreshold: env.memTableSize * 105 / 100,
		},
	}
}

// maybeThrottle slows down memtable flushing to match user write rate. The DB
// provides the total number of bytes in all the memtables. We subtract this total
// by the number of bytes flushed in the current flush to get a "dirty byte" count.
// If the dirty byte count is below the watermark (105% memtable size), the rate
// limiter is applied. If the dirty byte count is above the watermark, the rate
// limiter is not applied.
func (p *flushPacer) maybeThrottle(bytesIterated uint64) error {
	if bytesIterated == 0 {
		return nil
	}

	// Recalculate inuse memtable bytes only once every 1000 iterations or when
	// the refresh threshold is hit since getting the inuse memtable byte count
	// requires grabbing DB.mu which is expensive.
	if p.iterCount == 0 || bytesIterated > p.refreshBytesThreshold {
		pacerInfo := p.env.getInfo()
		p.iterCount = 1000
		p.refreshBytesThreshold = bytesIterated + (p.env.memTableSize * 5 / 100)
		p.adjustedInuseBytes = pacerInfo.inuseBytes
		if p.inuseBytes == pacerInfo.inuseBytes {
			// The inuse bytes in the memtables have not changed since the previous
			// call: user writes have completely stopped. Allow the flush to proceed
			// as fast as possible until the next recalculation. We adjust the
			// recalculation threshold so that we can be nimble in the face of new
			// user writes.
			p.adjustedInuseBytes += p.slowdownThreshold
			p.iterCount = 100
		}
		p.inuseBytes = pacerInfo.inuseBytes
	}
	p.iterCount--

	// dirtyBytes is the inuse number of bytes in the memtables minus the number of
	// bytes flushed. It represents unflushed bytes in all the memtables, even the
	// ones which aren't being flushed such as the mutable memtable.
	dirtyBytes := p.adjustedInuseBytes - bytesIterated
	flushAmount := bytesIterated - p.prevBytesIterated
	p.prevBytesIterated = bytesIterated

	// We slow down memtable flushing when the dirty bytes indicator falls
	// below the low watermark, which is 105% memtable size. This will only
	// occur if memtable flushing can keep up with the pace of incoming
	// writes. If writes come in faster than how fast the memtable can flush,
	// flushing proceeds at maximum (unthrottled) speed.
	return p.limit(flushAmount, dirtyBytes)
}

// deletionPacerInfo contains any info from the db necessary to make deletion
// pacing decisions.
type deletionPacerInfo struct {
	freeBytes     uint64
	obsoleteBytes uint64
	liveBytes     uint64
}

// deletionPacer rate limits deletions of obsolete files. This is necessary to
// prevent overloading the disk with too many deletions too quickly after a
// large compaction, or an iterator close. On some SSDs, disk performance can be
// negatively impacted if too many blocks are deleted very quickly, so this
// mechanism helps mitigate that.
type deletionPacer struct {
	limiter               limiter
	freeSpaceThreshold    uint64
	obsoleteBytesMaxRatio float64

	getInfo func() deletionPacerInfo
}

// newDeletionPacer instantiates a new deletionPacer for use when deleting
// obsolete files. The limiter passed in must be a singleton shared across this
// pebble instance.
func newDeletionPacer(limiter limiter, getInfo func() deletionPacerInfo) *deletionPacer {
	return &deletionPacer{
		limiter: limiter,
		// If there are less than freeSpaceThreshold bytes of free space on
		// disk, do not pace deletions at all.
		freeSpaceThreshold: 16 << 30, // 16 GB
		// If the ratio of obsolete bytes to live bytes is greater than
		// obsoleteBytesMaxRatio, do not pace deletions at all.
		obsoleteBytesMaxRatio: 0.20,

		getInfo: getInfo,
	}
}

// limit applies rate limiting if the current free disk space is more than
// freeSpaceThreshold, and the ratio of obsolete to live bytes is less than
// obsoleteBytesMaxRatio.
func (p *deletionPacer) limit(amount uint64, info deletionPacerInfo) error {
	obsoleteBytesRatio := float64(1.0)
	if info.liveBytes > 0 {
		obsoleteBytesRatio = float64(info.obsoleteBytes) / float64(info.liveBytes)
	}
	paceDeletions := info.freeBytes > p.freeSpaceThreshold &&
		obsoleteBytesRatio < p.obsoleteBytesMaxRatio
	if paceDeletions {
		burst := p.limiter.Burst()
		for amount > uint64(burst) {
			d := p.limiter.DelayN(time.Now(), burst)
			if d == rate.InfDuration {
				return errors.Errorf("pacing failed")
			}
			time.Sleep(d)
			amount -= uint64(burst)
		}
		d := p.limiter.DelayN(time.Now(), int(amount))
		if d == rate.InfDuration {
			return errors.Errorf("pacing failed")
		}
		time.Sleep(d)
	} else {
		burst := p.limiter.Burst()
		for amount > uint64(burst) {
			// AllowN will subtract burst if there are enough tokens available,
			// else leave the tokens untouched. That is, we are making a
			// best-effort to account for this activity in the limiter, but by
			// ignoring the return value, we do the activity instantaneously
			// anyway.
			p.limiter.AllowN(time.Now(), burst)
			amount -= uint64(burst)
		}
		p.limiter.AllowN(time.Now(), int(amount))
	}
	return nil
}

// maybeThrottle slows down a deletion of this file if it's faster than
// opts.Experimental.MinDeletionRate.
func (p *deletionPacer) maybeThrottle(bytesToDelete uint64) error {
	return p.limit(bytesToDelete, p.getInfo())
}

type noopPacer struct{}

func (p *noopPacer) maybeThrottle(_ uint64) error {
	return nil
}
