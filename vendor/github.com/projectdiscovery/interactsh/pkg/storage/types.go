package storage

import (
	"sync"
	"time"
)

type GetInteractionsFunc func() []string

type CacheMetrics struct {
	HitCount         uint64        `json:"hit-count"`
	MissCount        uint64        `json:"miss-count"`
	LoadSuccessCount uint64        `json:"load-success-count"`
	LoadErrorCount   uint64        `json:"load-error-count"`
	TotalLoadTime    time.Duration `json:"total-load-time"`
	EvictionCount    uint64        `json:"eviction-count"`
}

// CorrelationData is the data for a correlation-id.
type CorrelationData struct {
	sync.Mutex
	// data contains data for a correlation-id in AES encrypted json format.
	Data []string `json:"data"`
	// secretkey is a secret key for original user verification
	SecretKey string `json:"-"`
	// AESKey is the AES encryption key in encrypted format.
	AESKeyEncrypted string `json:"aes-key"`
	// decrypted AES key for signing
	AESKey []byte `json:"-"`
}
