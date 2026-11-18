package gcache

/*
Copyright 2012 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// This module provides a duplicate function call suppression
// mechanism.

import "sync"

// call is an in-flight or completed Do call
type call[V any] struct {
	wg  sync.WaitGroup
	val V
	err error
}

// Group represents a class of work and forms a namespace in which
// units of work can be executed with duplicate suppression.
type Group[K comparable, V any] struct {
	cache Cache[K, V]
	mu    sync.Mutex     // protects m
	m     map[K]*call[V] // lazily initialized

	// 用于快速返回泛型nil
	nilV V
}

// Do executes and returns the results of the given function, making
// sure that only one execution is in-flight for a given key at a
// time. If a duplicate comes in, the duplicate caller waits for the
// original to complete and receives the same results.
func (g *Group[K, V]) Do(key K, fn func() (V, error), isWait bool) (V, bool, error) {
	g.mu.Lock()
	v, err := g.cache.get(key, true)
	if err == nil {
		g.mu.Unlock()
		return v, false, nil
	}
	if g.m == nil {
		g.m = make(map[K]*call[V])
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		if !isWait {
			return g.nilV, false, KeyNotFoundError
		}
		c.wg.Wait()
		return c.val, false, c.err
	}
	c := new(call[V])
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()
	if !isWait {
		go g.call(c, key, fn)
		return g.nilV, false, KeyNotFoundError
	}
	v, err = g.call(c, key, fn)
	return v, true, err
}

func (g *Group[K, V]) call(c *call[V], key K, fn func() (V, error)) (V, error) {
	c.val, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()

	return c.val, c.err
}
