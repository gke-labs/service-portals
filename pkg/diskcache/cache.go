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

package diskcache

import (
	"container/list"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const defaultMaxBytes = 1 << 30 // 1 GiB

// ErrTooLarge is returned by Write when an entry exceeds MaxBytes.
var ErrTooLarge = errors.New("entry exceeds max cache size")

// Config configures a bounded-size on-disk LRU cache.
type Config struct {
	Dir      string
	MaxBytes int64
}

// InitDefaults sets default configuration values.
func (c *Config) InitDefaults() {
	c.MaxBytes = defaultMaxBytes
}

type entry struct {
	name string
	size int64
}

// Cache is a bounded-size, LRU-evicting on-disk cache.
type Cache struct {
	dir      string
	maxBytes int64

	mu         sync.Mutex
	lru        *list.List
	lruIndex   map[string]*list.Element
	totalBytes int64
}

// New creates a new on-disk cache rooted at cfg.Dir.
// Callers should call cfg.InitDefaults() before overriding fields; MaxBytes == 0
// leaves the cache unbounded.
func New(cfg Config) (*Cache, error) {
	if cfg.Dir == "" {
		return nil, errors.New("cache directory is required")
	}
	if cfg.MaxBytes < 0 {
		return nil, fmt.Errorf("max cache bytes must be non-negative, got %d", cfg.MaxBytes)
	}
	if err := os.MkdirAll(cfg.Dir, 0755); err != nil {
		return nil, fmt.Errorf("creating cache directory %q: %w", cfg.Dir, err)
	}
	c := &Cache{
		dir:      cfg.Dir,
		maxBytes: cfg.MaxBytes,
		lru:      list.New(),
		lruIndex: make(map[string]*list.Element),
	}
	if err := c.scanDir(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cache) scanDir() error {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return fmt.Errorf("scanning cache directory %q: %w", c.dir, err)
	}
	type diskEntry struct {
		name    string
		size    int64
		modTime time.Time
	}
	var found []diskEntry
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if strings.HasPrefix(name, ".tmp-") {
			logErr("removing stale temp file", os.Remove(filepath.Join(c.dir, name)))
			continue
		}
		if c.maxBytes == 0 {
			continue
		}
		info, err := de.Info()
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("stat cache entry %q: %w", name, err)
		}
		found = append(found, diskEntry{name: name, size: info.Size(), modTime: info.ModTime()})
	}
	if c.maxBytes == 0 {
		return nil
	}
	// Seed LRU order from ModTime so oldest entries sit at the back for eviction.
	slices.SortFunc(found, func(a, b diskEntry) int {
		if cmp := a.modTime.Compare(b.modTime); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.name, b.name)
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range found {
		if e.size > c.maxBytes {
			logErr("evicting oversized cache file", os.Remove(filepath.Join(c.dir, e.name)))
			continue
		}
		c.addEntryLocked(e.name, e.size)
	}
	c.evictLocked()
	return nil
}

// Open opens a cached entry for streaming reads and updates its LRU recency in
// memory without modifying the file's ModTime.
func (c *Cache) Open(key string) (*os.File, os.FileInfo, error) {
	name := fileName(key)
	f, err := os.Open(filepath.Join(c.dir, name))
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		logErr("closing cache file", f.Close())
		return nil, nil, err
	}
	// Update LRU in memory only; never touch ModTime so caller TTLs are not extended.
	c.touch(name)
	return f, info, nil
}

// Stat returns file metadata for a cached entry without updating LRU recency.
func (c *Cache) Stat(key string) (os.FileInfo, error) {
	return os.Stat(filepath.Join(c.dir, fileName(key)))
}

// Write atomically streams r into the cache under key.
// If expectedSize >= 0, Write verifies that exactly expectedSize bytes are read,
// returning io.ErrUnexpectedEOF otherwise. If MaxBytes > 0 and expectedSize or
// the stream exceeds MaxBytes, Write returns ErrTooLarge without modifying the
// cache. If modTime is non-zero, the file's mtime is set to modTime before rename.
func (c *Cache) Write(key string, r io.Reader, expectedSize int64, modTime time.Time) error {
	if c.maxBytes > 0 && expectedSize > c.maxBytes {
		return ErrTooLarge
	}
	tmp, err := os.CreateTemp(c.dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if c.maxBytes > 0 {
		r = io.LimitReader(r, c.maxBytes+1)
	}
	n, err := io.Copy(tmp, r)
	if err == nil && c.maxBytes > 0 && n > c.maxBytes {
		err = ErrTooLarge
	} else if err == nil && expectedSize >= 0 && n != expectedSize {
		err = io.ErrUnexpectedEOF
	}
	err = errors.Join(err, tmp.Close())
	if err == nil {
		if !modTime.IsZero() {
			logErr("setting mtime", os.Chtimes(tmpName, modTime, modTime))
		}
		name := fileName(key)
		dst := filepath.Join(c.dir, name)
		c.mu.Lock()
		err = os.Rename(tmpName, dst)
		if err == nil && c.maxBytes > 0 {
			c.addEntryLocked(name, n)
			c.evictLocked()
		}
		c.mu.Unlock()
	}
	if err != nil {
		logErr("removing temp file", os.Remove(tmpName))
	}
	return err
}

func fileName(key string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
}

func (c *Cache) touch(name string) {
	if c.maxBytes == 0 {
		return
	}
	c.mu.Lock()
	if elem, ok := c.lruIndex[name]; ok {
		c.lru.MoveToFront(elem)
	}
	c.mu.Unlock()
}

func (c *Cache) addEntryLocked(name string, size int64) {
	if elem, ok := c.lruIndex[name]; ok {
		e := elem.Value.(*entry)
		c.totalBytes += size - e.size
		e.size = size
		c.lru.MoveToFront(elem)
		return
	}
	c.lruIndex[name] = c.lru.PushFront(&entry{name: name, size: size})
	c.totalBytes += size
}

func (c *Cache) evictLocked() {
	for c.totalBytes > c.maxBytes {
		elem := c.lru.Back()
		if elem == nil {
			break
		}
		e := elem.Value.(*entry)
		c.lru.Remove(elem)
		delete(c.lruIndex, e.name)
		c.totalBytes -= e.size
		logErr("evicting cache file", os.Remove(filepath.Join(c.dir, e.name)))
	}
}

func logErr(desc string, err error) {
	if err != nil && !os.IsNotExist(err) {
		log.Printf("diskcache: %s: %v", desc, err)
	}
}
