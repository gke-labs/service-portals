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
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
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

// DiskCache is a filesystem-backed implementation of Cache.
type DiskCache struct {
	dir             string
	defaultTTL      time.Duration
	cleanupInterval time.Duration
	mu              sync.RWMutex
}

// NewDiskCache creates a new DiskCache rooted at dir and starts a background janitor.
func NewDiskCache(dir string, defaultTTL time.Duration, cleanupInterval time.Duration) (*DiskCache, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory %s: %w", dir, err)
	}
	if cleanupInterval <= 0 {
		cleanupInterval = 10 * time.Minute
	}
	c := &DiskCache{
		dir:             dir,
		defaultTTL:      defaultTTL,
		cleanupInterval: cleanupInterval,
	}
	go c.janitor()
	return c, nil
}

func (c *DiskCache) keyPath(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.dir, fmt.Sprintf("%x.cache", sum))
}

// Open retrieves an item from the disk cache as an io.ReadSeekCloser.
// The caller is responsible for closing the returned reader.
func (c *DiskCache) Open(key string) (io.ReadSeekCloser, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	p := c.keyPath(key)
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}

	if c.defaultTTL > 0 && time.Since(info.ModTime()) > c.defaultTTL {
		go func() {
			if err := os.Remove(p); err != nil {
				log.Printf("warning: removing expired cache file %s: %v", p, err)
			}
		}()
		return nil, os.ErrNotExist
	}

	// Explicitly update atime/mtime on access. Modern Linux/Unix filesystems typically
	// mount with "relatime" or "noatime" where read operations do not immediately update
	// file access times. Updating mtime ensures our TTL/LRU expiration check reliably sees
	// when the file was last accessed.
	now := time.Now()
	if err := os.Chtimes(p, now, now); err != nil {
		log.Printf("cache: failed to update access time for %s: %v", p, err)
	}

	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}

	return f, nil
}

// Get retrieves an item from the disk cache.
func (c *DiskCache) Get(key string) ([]byte, bool) {
	r, err := c.Open(key)
	if err != nil {
		return nil, false
	}
	defer func() {
		if err := r.Close(); err != nil {
			log.Printf("cache: failed to close reader for %s: %v", key, err)
		}
	}()

	val, err := io.ReadAll(r)
	if err != nil {
		return nil, false
	}

	return val, true
}

// Put streams an item into the disk cache from an io.Reader.
func (c *DiskCache) Put(key string, r io.Reader) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	tmpFile, err := os.CreateTemp(c.dir, "tmp-cache-*")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()

	if _, copyErr := io.Copy(tmpFile, r); copyErr != nil {
		closeErr := tmpFile.Close()
		if closeErr != nil {
			log.Printf("cache: failed to close temp file %s: %v", tmpName, closeErr)
		}
		if err := os.Remove(tmpName); err != nil {
			log.Printf("cache: failed to remove temp file %s: %v", tmpName, err)
		}
		return errors.Join(copyErr, closeErr)
	}

	if err := tmpFile.Close(); err != nil {
		if remErr := os.Remove(tmpName); remErr != nil {
			log.Printf("cache: failed to remove temp file %s: %v", tmpName, remErr)
		}
		return err
	}

	p := c.keyPath(key)
	now := time.Now()
	if err := os.Chtimes(tmpName, now, now); err != nil {
		log.Printf("cache: failed to touch temp file %s: %v", tmpName, err)
	}

	return os.Rename(tmpName, p)
}

// Set stores an item in the disk cache with a TTL.
func (c *DiskCache) Set(key string, value []byte, ttl time.Duration) {
	if ttl > 0 && c.defaultTTL <= 0 {
		c.defaultTTL = ttl
	}
	if err := c.Put(key, bytes.NewReader(value)); err != nil {
		log.Printf("cache: failed to store %s: %v", key, err)
	}
}

// Delete removes an item from the disk cache.
func (c *DiskCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := os.Remove(c.keyPath(key)); err != nil && !os.IsNotExist(err) {
		log.Printf("cache: failed to remove %s: %v", key, err)
	}
}

func (c *DiskCache) janitor() {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		if c.defaultTTL > 0 {
			now := time.Now()
			entries, err := os.ReadDir(c.dir)
			if err != nil {
				log.Printf("cache: janitor failed to read directory %s: %v", c.dir, err)
			} else {
				for _, entry := range entries {
					if entry.IsDir() || filepath.Ext(entry.Name()) != ".cache" {
						continue
					}
					fullPath := filepath.Join(c.dir, entry.Name())
					info, err := entry.Info()
					if err != nil {
						log.Printf("cache: janitor failed to stat %s: %v", fullPath, err)
						continue
					}
					if now.Sub(info.ModTime()) > c.defaultTTL {
						if err := os.Remove(fullPath); err != nil {
							log.Printf("cache: janitor failed to remove expired file %s: %v", fullPath, err)
						}
					}
				}
			}
		}
		c.mu.Unlock()
	}
}
