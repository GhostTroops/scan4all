// storage defines a storage mechanism
package storage

type Storage interface {
	GetCacheMetrics() (*CacheMetrics, error)
	SetIDPublicKey(correlationID, secretKey, publicKey string) error
	SetID(ID string) error
	AddInteraction(correlationID string, data []byte) error
	AddInteractionWithId(id string, data []byte) error
	GetInteractions(correlationID, secret string) ([]string, string, error)
	GetInteractionsWithId(id string) ([]string, error)
	RemoveID(correlationID, secret string) error
	GetCacheItem(token string) (*CorrelationData, error)
	Close() error
}
