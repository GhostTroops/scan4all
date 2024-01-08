//go:build (!amd64 && !arm64) || (arm64 && !go1.16)
// +build !amd64,!arm64 arm64,!go1.16

package keccakf1600

func permuteSIMDx2(state []uint64, turbo bool) { permuteScalarX2(state, turbo) }

func permuteSIMDx4(state []uint64, turbo bool) { permuteScalarX4(state, turbo) }
