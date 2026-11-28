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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func dirBytes(t *testing.T, dir string) int64 {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			t.Fatalf("Info(%s): %v", e.Name(), err)
		}
		total += info.Size()
	}
	return total
}

func readEntry(t *testing.T, c *Cache, key string) (string, os.FileInfo) {
	t.Helper()
	f, info, err := c.Open(key)
	if err != nil {
		t.Fatalf("Open(%q): %v", key, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("Close(%q): %v", key, err)
		}
	}()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("ReadAll(%q): %v", key, err)
	}
	return string(data), info
}

func TestConfigValidation(t *testing.T) {
	t.Run("InitDefaults sets 1 GiB", func(t *testing.T) {
		var cfg Config
		cfg.InitDefaults()
		if cfg.MaxBytes != 1<<30 {
			t.Fatalf("InitDefaults().MaxBytes = %d, want %d", cfg.MaxBytes, 1<<30)
		}
	})

	t.Run("empty Dir rejected", func(t *testing.T) {
		var cfg Config
		cfg.InitDefaults()
		if _, err := New(cfg); err == nil {
			t.Fatal("New accepted empty Dir, want error")
		}
	})

	t.Run("negative MaxBytes rejected", func(t *testing.T) {
		if _, err := New(Config{Dir: t.TempDir(), MaxBytes: -1}); err == nil {
			t.Fatal("New accepted negative MaxBytes, want error")
		}
	})

	t.Run("zero MaxBytes stays unbounded and cleans stale temp files", func(t *testing.T) {
		dir := t.TempDir()
		tmpFile := filepath.Join(dir, ".tmp-stale")
		if err := os.WriteFile(tmpFile, []byte("stale"), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		c, err := New(Config{Dir: dir})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if c.maxBytes != 0 {
			t.Fatalf("maxBytes = %d, want 0", c.maxBytes)
		}
		if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
			t.Fatalf("stale temp file still exists: err=%v", err)
		}
		now := time.Now().Truncate(time.Second)
		for _, k := range []string{"k1", "k2", "k3"} {
			body := strings.Repeat(k, 32)
			if err := c.Write(k, strings.NewReader(body), int64(len(body)), now); err != nil {
				t.Fatalf("Write(%q): %v", k, err)
			}
		}
		for _, k := range []string{"k1", "k2", "k3"} {
			got, _ := readEntry(t, c, k)
			if want := strings.Repeat(k, 32); got != want {
				t.Fatalf("Open(%q) = %q, want %q", k, got, want)
			}
		}
	})
}

func TestStartupScanAndTempCleanup(t *testing.T) {
	t.Run("seeds LRU from ModTime, ignores subdirs, removes stale temp and oversized files", func(t *testing.T) {
		dir := t.TempDir()
		oldFile := filepath.Join(dir, fileName("old"))
		newFile := filepath.Join(dir, fileName("new"))
		hugeFile := filepath.Join(dir, fileName("huge"))
		tmpFile := filepath.Join(dir, ".tmp-crashed-12345")
		subDir := filepath.Join(dir, "subdir")

		if err := os.Mkdir(subDir, 0755); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		if err := os.WriteFile(oldFile, []byte("0123456789"), 0644); err != nil {
			t.Fatalf("WriteFile old: %v", err)
		}
		if err := os.WriteFile(newFile, []byte("abcdefghij"), 0644); err != nil {
			t.Fatalf("WriteFile new: %v", err)
		}
		if err := os.WriteFile(hugeFile, []byte(strings.Repeat("H", 25)), 0644); err != nil {
			t.Fatalf("WriteFile huge: %v", err)
		}
		if err := os.WriteFile(tmpFile, []byte("partial"), 0644); err != nil {
			t.Fatalf("WriteFile tmp: %v", err)
		}
		base := time.Now().Add(-time.Hour).Truncate(time.Second)
		if err := os.Chtimes(oldFile, base, base); err != nil {
			t.Fatalf("Chtimes old: %v", err)
		}
		if err := os.Chtimes(newFile, base.Add(time.Minute), base.Add(time.Minute)); err != nil {
			t.Fatalf("Chtimes new: %v", err)
		}

		c, err := New(Config{Dir: dir, MaxBytes: 20})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
			t.Fatalf("stale temp file still exists: err=%v", err)
		}
		if _, err := os.Stat(hugeFile); !os.IsNotExist(err) {
			t.Fatalf("oversized pre-existing file still exists: err=%v", err)
		}
		if _, err := os.Stat(subDir); err != nil {
			t.Fatalf("subdir should be untouched: err=%v", err)
		}

		// Writing a 10B entry pushes total to 30B > 20B, evicting older entry "old".
		if err := c.Write("fresh", strings.NewReader("ZZZZZZZZZZ"), 10, base.Add(2*time.Minute)); err != nil {
			t.Fatalf("Write fresh: %v", err)
		}
		if _, err := c.Stat("old"); !os.IsNotExist(err) {
			t.Fatalf("expected oldest pre-existing entry evicted, err=%v", err)
		}
		if got, _ := readEntry(t, c, "new"); got != "abcdefghij" {
			t.Fatalf("Open(new) = %q, want abcdefghij", got)
		}
		if got := dirBytes(t, dir); got != 20 {
			t.Fatalf("dirBytes = %d, want 20", got)
		}
	})

	t.Run("evicts pre-existing excess on startup", func(t *testing.T) {
		dir := t.TempDir()
		oldFile := filepath.Join(dir, fileName("old"))
		newFile := filepath.Join(dir, fileName("new"))
		if err := os.WriteFile(oldFile, []byte("0123456789"), 0644); err != nil {
			t.Fatalf("WriteFile old: %v", err)
		}
		if err := os.WriteFile(newFile, []byte("abcdefghij"), 0644); err != nil {
			t.Fatalf("WriteFile new: %v", err)
		}
		base := time.Now().Add(-time.Hour).Truncate(time.Second)
		if err := os.Chtimes(oldFile, base, base); err != nil {
			t.Fatalf("Chtimes old: %v", err)
		}
		if err := os.Chtimes(newFile, base.Add(time.Minute), base.Add(time.Minute)); err != nil {
			t.Fatalf("Chtimes new: %v", err)
		}

		c, err := New(Config{Dir: dir, MaxBytes: 10})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := c.Stat("old"); !os.IsNotExist(err) {
			t.Fatalf("expected old entry evicted on startup, err=%v", err)
		}
		if _, err := c.Stat("new"); err != nil {
			t.Fatalf("expected new entry kept on startup, err=%v", err)
		}
		if got := dirBytes(t, dir); got != 10 {
			t.Fatalf("dirBytes = %d, want 10", got)
		}
	})
}

func TestLRUEvictionAndOverwrite(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{Dir: dir, MaxBytes: 20})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Now().Truncate(time.Second)

	if err := c.Write("a", strings.NewReader(strings.Repeat("a", 10)), 10, now); err != nil {
		t.Fatalf("Write a: %v", err)
	}
	if err := c.Write("b", strings.NewReader(strings.Repeat("b", 10)), 10, now); err != nil {
		t.Fatalf("Write b: %v", err)
	}

	// Open "a" so "b" becomes LRU; Stat "b" must not promote "b".
	if got, _ := readEntry(t, c, "a"); got != strings.Repeat("a", 10) {
		t.Fatalf("Open(a) = %q", got)
	}
	if _, err := c.Stat("b"); err != nil {
		t.Fatalf("Stat(b): %v", err)
	}

	// Writing "c" (10B) must evict "b" and keep "a".
	if err := c.Write("c", strings.NewReader(strings.Repeat("c", 10)), 10, now); err != nil {
		t.Fatalf("Write c: %v", err)
	}
	if _, err := c.Stat("b"); !os.IsNotExist(err) {
		t.Fatalf("expected b evicted, err=%v", err)
	}
	if _, err := c.Stat("a"); err != nil {
		t.Fatalf("expected a retained, err=%v", err)
	}
	if got := dirBytes(t, dir); got != 20 {
		t.Fatalf("dirBytes = %d, want 20", got)
	}

	// Overwriting "a" with a smaller payload updates totalBytes accurately.
	if err := c.Write("a", strings.NewReader("short"), 5, now.Add(time.Minute)); err != nil {
		t.Fatalf("overwrite a: %v", err)
	}
	if got, want := c.totalBytes, dirBytes(t, dir); got != want || got != 15 {
		t.Fatalf("totalBytes = %d (disk %d), want 15", got, want)
	}
}

func TestOpenPreservesModTime(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{Dir: dir, MaxBytes: 1024})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wantMod := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	if err := c.Write("mutable", strings.NewReader("v1"), 2, wantMod); err != nil {
		t.Fatalf("Write: %v", err)
	}

	infoBefore, err := c.Stat("mutable")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !infoBefore.ModTime().Equal(wantMod) {
		t.Fatalf("ModTime = %v, want %v", infoBefore.ModTime(), wantMod)
	}

	for range 3 {
		got, info := readEntry(t, c, "mutable")
		if got != "v1" {
			t.Fatalf("Open = %q, want v1", got)
		}
		if !info.ModTime().Equal(wantMod) {
			t.Fatalf("ModTime changed on Open: got %v, want %v", info.ModTime(), wantMod)
		}
	}
	infoAfter, err := c.Stat("mutable")
	if err != nil {
		t.Fatalf("Stat after reads: %v", err)
	}
	if !infoAfter.ModTime().Equal(wantMod) {
		t.Fatalf("ModTime changed after Open: got %v, want %v", infoAfter.ModTime(), wantMod)
	}
}

func TestWriteErrors(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{Dir: dir, MaxBytes: 20})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Now().Truncate(time.Second)

	// Seed a small entry that must survive failed/oversized writes.
	if err := c.Write("small", strings.NewReader("small"), 5, now); err != nil {
		t.Fatalf("Write small: %v", err)
	}

	t.Run("expectedSize exceeds MaxBytes", func(t *testing.T) {
		err := c.Write("big-known", strings.NewReader(strings.Repeat("B", 50)), 50, now)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Write = %v, want ErrTooLarge", err)
		}
	})

	t.Run("unknown-length stream exceeds MaxBytes", func(t *testing.T) {
		err := c.Write("big-stream", strings.NewReader(strings.Repeat("S", 50)), -1, now)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Write = %v, want ErrTooLarge", err)
		}
	})

	t.Run("short stream returns ErrUnexpectedEOF", func(t *testing.T) {
		err := c.Write("short", strings.NewReader("abc"), 10, now)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("Write = %v, want ErrUnexpectedEOF", err)
		}
	})

	t.Run("long stream returns ErrUnexpectedEOF", func(t *testing.T) {
		err := c.Write("long", strings.NewReader("abcdef"), 3, now)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("Write = %v, want ErrUnexpectedEOF", err)
		}
	})

	// Existing entry must remain untouched and no temp files left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || dirBytes(t, dir) != 5 {
		t.Fatalf("unexpected cache state: entries=%d bytes=%d", len(entries), dirBytes(t, dir))
	}
	if got, _ := readEntry(t, c, "small"); got != "small" {
		t.Fatalf("Open(small) = %q, want small", got)
	}
}

func TestConcurrentReadsWritesEvictions(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{Dir: dir, MaxBytes: 128})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan string, 200)
	for g := range 10 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range 25 {
				key := fmt.Sprintf("key-%d-%d", id, i%5)
				val := fmt.Sprintf("payload-%d-%d", id, i%5)
				if err := c.Write(key, strings.NewReader(val), int64(len(val)), time.Now()); err != nil {
					errs <- fmt.Sprintf("Write(%s): %v", key, err)
					return
				}
				f, _, err := c.Open(key)
				if err != nil {
					if os.IsNotExist(err) {
						continue // evicted concurrently
					}
					errs <- fmt.Sprintf("Open(%s): %v", key, err)
					return
				}
				data, readErr := io.ReadAll(f)
				closeErr := f.Close()
				if readErr != nil || closeErr != nil {
					errs <- fmt.Sprintf("Read/Close(%s): %v / %v", key, readErr, closeErr)
					return
				}
				if string(data) != val {
					errs <- fmt.Sprintf("Open(%s) = %q, want %q", key, string(data), val)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Fatal(msg)
	}
	if got := dirBytes(t, dir); got > 128 {
		t.Fatalf("dirBytes = %d, want <= 128", got)
	}
	if got, want := c.totalBytes, dirBytes(t, dir); got != want {
		t.Fatalf("totalBytes = %d, want %d", got, want)
	}
}
