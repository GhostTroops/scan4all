package pogreb

import (
	"errors"
	"sync"
)

// ErrIterationDone is returned by ItemIterator.Next calls when there are no more items to return.
var ErrIterationDone = errors.New("no more items in iterator")

type item struct {
	key   []byte
	value []byte
}

// ItemIterator is an iterator over DB key-value pairs. It iterates the items in an unspecified order.
type ItemIterator struct {
	db            *DB
	nextBucketIdx uint32
	queue         []item
	mu            sync.Mutex
}

// fetchItems adds items to the iterator queue from a bucket located at nextBucketIdx.
func (it *ItemIterator) fetchItems(nextBucketIdx uint32) error {
	bit := it.db.index.newBucketIterator(nextBucketIdx)
	for {
		b, err := bit.next()
		if err == ErrIterationDone {
			return nil
		}
		if err != nil {
			return err
		}
		for i := 0; i < slotsPerBucket; i++ {
			sl := b.slots[i]
			if sl.offset == 0 {
				// No more items in the bucket.
				break
			}
			key, value, err := it.db.datalog.readKeyValue(sl)
			if err != nil {
				return err
			}
			key = cloneBytes(key)
			value = cloneBytes(value)
			it.queue = append(it.queue, item{key: key, value: value})
		}
	}
}

// Next returns the next key-value pair if available, otherwise it returns ErrIterationDone error.
func (it *ItemIterator) Next() ([]byte, []byte, error) {
	it.mu.Lock()
	defer it.mu.Unlock()

	it.db.mu.RLock()
	defer it.db.mu.RUnlock()

	// The iterator queue is empty and we have more buckets to check.
	for len(it.queue) == 0 && it.nextBucketIdx < it.db.index.numBuckets {
		if err := it.fetchItems(it.nextBucketIdx); err != nil {
			return nil, nil, err
		}
		it.nextBucketIdx++
	}

	if len(it.queue) > 0 {
		item := it.queue[0]
		it.queue = it.queue[1:]
		return item.key, item.value, nil
	}

	return nil, nil, ErrIterationDone
}
