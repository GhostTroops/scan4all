/*
 * Copyright (c) 2019, Psiphon Inc.
 * All rights reserved.
 *
 * Released under utls licence:
 * https://github.com/refraction-networking/utls/blob/master/LICENSE
 */

// This code is a pared down version of:
// https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/158caea562287284cc3fa5fcd1b3c97b1addf659/psiphon/common/prng/prng.go

package tls

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	"io"
	"math"
	"math/rand"
	"sync"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	PRNGSeedLength = 32
)

// PRNGSeed is a PRNG seed.
type PRNGSeed [PRNGSeedLength]byte

// NewPRNGSeed creates a new PRNG seed using crypto/rand.Read.
func NewPRNGSeed() (*PRNGSeed, error) {
	seed := new(PRNGSeed)
	_, err := crypto_rand.Read(seed[:])
	if err != nil {
		return nil, err
	}
	return seed, nil
}

// newSaltedPRNGSeed creates a new seed derived from an existing seed and a
// salt. A HKDF is applied to the seed and salt.
//
// newSaltedPRNGSeed is intended for use cases where a single seed needs to be
// used in distinct contexts to produce independent random streams.
func newSaltedPRNGSeed(seed *PRNGSeed, salt string) (*PRNGSeed, error) {
	saltedSeed := new(PRNGSeed)
	_, err := io.ReadFull(
		hkdf.New(sha3.New256, seed[:], []byte(salt), nil), saltedSeed[:])
	if err != nil {
		return nil, err
	}
	return saltedSeed, nil
}

// prng is a seeded, unbiased PRNG based on SHAKE256. that is suitable for use
// cases such as obfuscation. Seeding is based on crypto/rand.Read.
//
// This PRNG is _not_ for security use cases including production cryptographic
// key generation.
//
// It is safe to make concurrent calls to a PRNG instance.
//
// PRNG conforms to io.Reader and math/rand.Source, with additional helper
// functions.
type prng struct {
	rand              *rand.Rand
	randomStreamMutex sync.Mutex
	randomStream      sha3.ShakeHash
}

// newPRNG generates a seed and creates a PRNG with that seed.
func newPRNG() (*prng, error) {
	seed, err := NewPRNGSeed()
	if err != nil {
		return nil, err
	}
	return newPRNGWithSeed(seed)
}

// newPRNGWithSeed initializes a new PRNG using an existing seed.
func newPRNGWithSeed(seed *PRNGSeed) (*prng, error) {
	shake := sha3.NewShake256()
	_, err := shake.Write(seed[:])
	if err != nil {
		return nil, err
	}
	p := &prng{
		randomStream: shake,
	}
	p.rand = rand.New(p)
	return p, nil
}

// newPRNGWithSaltedSeed initializes a new PRNG using a seed derived from an
// existing seed and a salt with NewSaltedSeed.
func newPRNGWithSaltedSeed(seed *PRNGSeed, salt string) (*prng, error) {
	saltedSeed, err := newSaltedPRNGSeed(seed, salt)
	if err != nil {
		return nil, err
	}
	return newPRNGWithSeed(saltedSeed)
}

// Read reads random bytes from the PRNG stream into b. Read conforms to
// io.Reader and always returns len(p), nil.
func (p *prng) Read(b []byte) (int, error) {
	p.randomStreamMutex.Lock()
	defer p.randomStreamMutex.Unlock()

	// ShakeHash.Read never returns an error:
	// https://godoc.org/golang.org/x/crypto/sha3#ShakeHash
	_, _ = io.ReadFull(p.randomStream, b)

	return len(b), nil
}

// Int63 is equivalent to math/read.Int63.
func (p *prng) Int63() int64 {
	i := p.Uint64()
	return int64(i & (1<<63 - 1))
}

// Int63 is equivalent to math/read.Uint64.
func (p *prng) Uint64() uint64 {
	var b [8]byte
	p.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}

// Seed must exist in order to use a PRNG as a math/rand.Source. This call is
// not supported and ignored.
func (p *prng) Seed(_ int64) {
}

// FlipWeightedCoin returns the result of a weighted
// random coin flip. If the weight is 0.5, the outcome
// is equally likely to be true or false. If the weight
// is 1.0, the outcome is always true, and if the
// weight is 0.0, the outcome is always false.
//
// Input weights > 1.0 are treated as 1.0.
func (p *prng) FlipWeightedCoin(weight float64) bool {
	if weight > 1.0 {
		weight = 1.0
	}
	f := float64(p.Int63()) / float64(math.MaxInt64)
	return f > 1.0-weight
}

// Intn is equivalent to math/read.Intn, except it returns 0 if n <= 0
// instead of panicking.
func (p *prng) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	return p.rand.Intn(n)
}

// Int63n is equivalent to math/read.Int63n, except it returns 0 if n <= 0
// instead of panicking.
func (p *prng) Int63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return p.rand.Int63n(n)
}

// Intn is equivalent to math/read.Perm.
func (p *prng) Perm(n int) []int {
	return p.rand.Perm(n)
}

// Range selects a random integer in [min, max].
// If min < 0, min is set to 0. If max < min, min is returned.
func (p *prng) Range(min, max int) int {
	if min < 0 {
		min = 0
	}
	if max < min {
		return min
	}
	n := p.Intn(max - min + 1)
	n += min
	return n
}
