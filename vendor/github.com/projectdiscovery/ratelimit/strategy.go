package ratelimit

type Strategy uint8

const (
	None Strategy = iota
	LeakyBucket
)
