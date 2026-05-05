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
	"testing"
	"time"
)

func TestInMemoryCache(t *testing.T) {
	c := NewInMemoryCache(0)

	// Test Set and Get
	c.Set("key1", []byte("value1"), 1*time.Minute)
	val, ok := c.Get("key1")
	if !ok {
		t.Fatal("Expected to find key1")
	}
	if !bytes.Equal(val, []byte("value1")) {
		t.Errorf("Expected value1, got %s", val)
	}

	// Test Delete
	c.Delete("key1")
	_, ok = c.Get("key1")
	if ok {
		t.Fatal("Expected key1 to be deleted")
	}

	// Test Expiration
	c.Set("key2", []byte("value2"), 1*time.Millisecond)
	time.Sleep(2 * time.Millisecond)
	_, ok = c.Get("key2")
	if ok {
		t.Fatal("Expected key2 to be expired")
	}
}
