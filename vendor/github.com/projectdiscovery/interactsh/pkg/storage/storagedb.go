// storage implements a encrypted memory mechanism
package storage

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"

	"github.com/goburrow/cache"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/fileutil"
	"github.com/rs/xid"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"go.uber.org/multierr"
)

// Storage is an storage for interactsh interaction data as well
// as correlation-id -> rsa-public-key data.
type StorageDB struct {
	Options *Options
	cache   cache.Cache
	db      *leveldb.DB
	dbpath  string
}

// New creates a new storage instance for interactsh data.
func New(options *Options) (*StorageDB, error) {
	storageDB := &StorageDB{Options: options}
	cacheOptions := []cache.Option{
		cache.WithMaximumSize(options.MaxSize),
		cache.WithExpireAfterWrite(options.EvictionTTL),
	}
	if options.UseDisk() {
		cacheOptions = append(cacheOptions, cache.WithRemovalListener(storageDB.OnCacheRemovalCallback))
	}
	cacheDb := cache.New(cacheOptions...)
	storageDB.cache = cacheDb

	if options.UseDisk() {
		// if the path exists we create a random temporary subfolder
		if !fileutil.FolderExists(options.DbPath) {
			return nil, errors.New("folder doesn't exist")
		}
		dbpath := filepath.Join(options.DbPath, xid.New().String())

		if err := os.MkdirAll(dbpath, 0644); err != nil {
			return nil, err
		}
		levDb, err := leveldb.OpenFile(dbpath, &opt.Options{})
		if err != nil {
			return nil, err
		}
		storageDB.dbpath = dbpath
		storageDB.db = levDb
	}

	return storageDB, nil
}

func (s *StorageDB) OnCacheRemovalCallback(key cache.Key, value cache.Value) {
	if key, ok := value.([]byte); ok {
		_ = s.db.Delete(key, &opt.WriteOptions{})
	}
}

func (s *StorageDB) GetCacheMetrics() (*CacheMetrics, error) {
	info := &cache.Stats{}
	s.cache.Stats(info)

	cacheMetrics := &CacheMetrics{
		HitCount:         info.HitCount,
		MissCount:        info.MissCount,
		LoadSuccessCount: info.LoadSuccessCount,
		LoadErrorCount:   info.LoadErrorCount,
		TotalLoadTime:    info.TotalLoadTime,
		EvictionCount:    info.EvictionCount,
	}

	return cacheMetrics, nil
}

// SetIDPublicKey sets the correlation ID and publicKey into the cache for further operations.
func (s *StorageDB) SetIDPublicKey(correlationID, secretKey, publicKey string) error {
	// If we already have this correlation ID, return.
	_, found := s.cache.GetIfPresent(correlationID)
	if found {
		return errors.New("correlation-id provided already exists")
	}
	publicKeyData, err := ParseB64RSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return errors.Wrap(err, "could not read public Key")
	}
	aesKey := uuid.New().String()[:32]

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKeyData, []byte(aesKey), []byte(""))
	if err != nil {
		return errors.New("could not encrypt event data")
	}

	data := &CorrelationData{
		SecretKey:       secretKey,
		AESKey:          []byte(aesKey),
		AESKeyEncrypted: base64.StdEncoding.EncodeToString(ciphertext),
	}
	s.cache.Put(correlationID, data)
	return nil
}

func (s *StorageDB) SetID(ID string) error {
	data := &CorrelationData{}
	s.cache.Put(ID, data)
	return nil
}

// AddInteraction adds an interaction data to the correlation ID after encrypting
// it with Public Key for the provided correlation ID.
func (s *StorageDB) AddInteraction(correlationID string, data []byte) error {
	item, found := s.cache.GetIfPresent(correlationID)
	if !found {
		return errors.New("could not get correlation-id from cache")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return errors.New("invalid correlation-id cache value found")
	}

	if s.Options.UseDisk() {
		ct, err := AESEncrypt(value.AESKey, data)
		if err != nil {
			return errors.Wrap(err, "could not encrypt event data")
		}
		value.Lock()
		existingData, _ := s.db.Get([]byte(correlationID), nil)
		_ = s.db.Put([]byte(correlationID), AppendMany("\n", existingData, []byte(ct)), nil)
		value.Unlock()
	} else {
		value.Lock()
		value.Data = append(value.Data, string(data))
		value.Unlock()
	}

	return nil
}

// AddInteractionWithId adds an interaction data to the id bucket
func (s *StorageDB) AddInteractionWithId(id string, data []byte) error {
	item, ok := s.cache.GetIfPresent(id)
	if !ok {
		return errors.New("could not get correlation-id from cache")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return errors.New("invalid correlation-id cache value found")
	}

	if s.Options.UseDisk() {
		ct, err := AESEncrypt(value.AESKey, data)
		if err != nil {
			return errors.Wrap(err, "could not encrypt event data")
		}
		value.Lock()
		existingData, _ := s.db.Get([]byte(id), nil)
		_ = s.db.Put([]byte(id), AppendMany("\n", existingData, []byte(ct)), nil)
		value.Unlock()
	} else {
		value.Lock()
		value.Data = append(value.Data, string(data))
		value.Unlock()
	}

	return nil
}

// GetInteractions returns the interactions for a correlationID and removes
// it from the storage. It also returns AES Encrypted Key for the IDs.
func (s *StorageDB) GetInteractions(correlationID, secret string) ([]string, string, error) {
	item, ok := s.cache.GetIfPresent(correlationID)
	if !ok {
		return nil, "", errors.New("could not get correlation-id from cache")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return nil, "", errors.New("invalid correlation-id cache value found")
	}
	if !strings.EqualFold(value.SecretKey, secret) {
		return nil, "", errors.New("invalid secret key passed for user")
	}
	data, err := s.getInteractions(value, correlationID)
	return data, value.AESKeyEncrypted, err
}

// GetInteractions returns the interactions for a id and empty the cache
func (s *StorageDB) GetInteractionsWithId(id string) ([]string, error) {
	item, ok := s.cache.GetIfPresent(id)
	if !ok {
		return nil, errors.New("could not get id from cache")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return nil, errors.New("invalid id cache value found")
	}
	return s.getInteractions(value, id)
}

// RemoveID removes data for a correlation ID and data related to it.
func (s *StorageDB) RemoveID(correlationID, secret string) error {
	item, ok := s.cache.GetIfPresent(correlationID)
	if !ok {
		return errors.New("could not get correlation-id from cache")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return errors.New("invalid correlation-id cache value found")
	}
	if !strings.EqualFold(value.SecretKey, secret) {
		return errors.New("invalid secret key passed for deregister")
	}
	value.Lock()
	value.Data = nil
	value.Unlock()
	s.cache.Invalidate(correlationID)

	if s.Options.UseDisk() {
		return s.db.Delete([]byte(correlationID), nil)
	}
	return nil
}

// GetCacheItem returns an item as is
func (s *StorageDB) GetCacheItem(token string) (*CorrelationData, error) {
	item, ok := s.cache.GetIfPresent(token)
	if !ok {
		return nil, errors.New("cache item not found")
	}
	value, ok := item.(*CorrelationData)
	if !ok {
		return nil, errors.New("cache item not found")
	}
	return value, nil
}

func (s *StorageDB) getInteractions(correlationData *CorrelationData, id string) ([]string, error) {
	correlationData.Lock()
	defer correlationData.Unlock()

	switch {
	case s.Options.UseDisk():
		data, err := s.db.Get([]byte(id), nil)
		if err != nil {
			if errors.Is(err, leveldb.ErrNotFound) {
				err = nil
			}
			return nil, err
		}
		var dataString []string
		for _, d := range bytes.Split(data, []byte("\n")) {
			dataString = append(dataString, string(d))
		}
		_ = s.db.Delete([]byte(id), nil)
		return dataString, nil
	default:
		// in memory data
		var errs []error
		data := correlationData.Data
		correlationData.Data = nil
		if len(data) == 0 {
			return nil, nil
		}

		for i, dataItem := range data {
			encryptedDataItem, err := AESEncrypt(correlationData.AESKey, []byte(dataItem))
			if err != nil {
				errs = append(errs, errors.Wrap(err, "could not encrypt event data"))
				continue
			}
			data[i] = encryptedDataItem
		}
		return data, multierr.Combine(errs...)
	}
}

func (s *StorageDB) Close() error {
	var errdbClosed error
	if s.db != nil {
		errdbClosed = s.db.Close()
	}
	return multierr.Combine(
		s.cache.Close(),
		errdbClosed,
		os.RemoveAll(s.dbpath),
	)
}
