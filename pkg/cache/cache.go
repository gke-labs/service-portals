// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cache

import (
	"sync"
	"time"
)

// Cache defines the interface for a simple cache.
type Cache interface {
	Get(key string) ([]byte, bool)
	Set(key string, value []byte, ttl time.Duration)
	Delete(key string)
}

type cacheItem struct {
	value      []byte
	expiration time.Time
}

// InMemoryCache is an in-memory implementation of Cache.
type InMemoryCache struct {
	mu              sync.RWMutex
	items           map[string]cacheItem
	cleanupInterval time.Duration
}

// NewInMemoryCache creates a new InMemoryCache and starts a background janitor to clean up expired items.
func NewInMemoryCache(cleanupInterval time.Duration) *InMemoryCache {
	if cleanupInterval <= 0 {
		cleanupInterval = 1 * time.Minute
	}
	c := &InMemoryCache{
		items:           make(map[string]cacheItem),
		cleanupInterval: cleanupInterval,
	}
	go c.janitor()
	return c
}

// Get retrieves an item from the cache.
func (c *InMemoryCache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, ok := c.items[key]
	if !ok {
		return nil, false
	}

	if time.Now().After(item.expiration) {
		return nil, false
	}

	return item.value, true
}

// Set adds an item to the cache with a TTL.
func (c *InMemoryCache) Set(key string, value []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = cacheItem{
		value:      value,
		expiration: time.Now().Add(ttl),
	}
}

// Delete removes an item from the cache.
func (c *InMemoryCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.items, key)
}

func (c *InMemoryCache) janitor() {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, v := range c.items {
			if now.After(v.expiration) {
				delete(c.items, k)
			}
		}
		c.mu.Unlock()
	}
}
