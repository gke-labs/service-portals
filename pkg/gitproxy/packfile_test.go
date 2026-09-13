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

package gitproxy

import (
	"bytes"
	"testing"
)

func TestPackfileBuildAndParseRoundtrip(t *testing.T) {
	blob1Data := []byte("Hello World!\n")
	blob1OID := ComputeOID(ObjBlob, blob1Data)
	blob1 := &RawObject{
		Type: ObjBlob,
		Data: blob1Data,
		OID:  blob1OID,
	}

	blob2Data := []byte("Another file content here...")
	blob2OID := ComputeOID(ObjBlob, blob2Data)
	blob2 := &RawObject{
		Type: ObjBlob,
		Data: blob2Data,
		OID:  blob2OID,
	}

	commitData := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor Test User <test@example.com> 1700000000 +0000\ncommitter Test User <test@example.com> 1700000000 +0000\n\nInitial commit\n")
	commitOID := ComputeOID(ObjCommit, commitData)
	commit := &RawObject{
		Type: ObjCommit,
		Data: commitData,
		OID:  commitOID,
	}

	objects := []*RawObject{commit, blob1, blob2}

	packBytes, err := BuildPackfile(objects)
	if err != nil {
		t.Fatalf("BuildPackfile failed: %v", err)
	}

	if len(packBytes) < 32 {
		t.Fatalf("packfile too small: %d bytes", len(packBytes))
	}

	parsedObjects, err := ParsePackfile(packBytes)
	if err != nil {
		t.Fatalf("ParsePackfile failed: %v", err)
	}

	if len(parsedObjects) != len(objects) {
		t.Fatalf("expected %d parsed objects, got %d", len(objects), len(parsedObjects))
	}

	for i, obj := range objects {
		parsed := parsedObjects[i]
		if parsed.Type != obj.Type {
			t.Errorf("obj %d: expected type %d, got %d", i, obj.Type, parsed.Type)
		}
		if parsed.OID != obj.OID {
			t.Errorf("obj %d: expected OID %s, got %s", i, obj.OID, parsed.OID)
		}
		if !bytes.Equal(parsed.Data, obj.Data) {
			t.Errorf("obj %d: payload mismatch", i)
		}
	}
}

func TestApplyDelta(t *testing.T) {
	base := []byte("The quick brown fox jumps over the lazy dog.")

	// Create delta that modifies "lazy dog" to "sleepy cat"
	// Delta header:
	// srcSize = 44 (0x2c)
	// targetSize = 46 (0x2e)
	// copy first 35 bytes ("The quick brown fox jumps over the ")
	// insert "sleepy cat." (11 bytes)
	var delta []byte
	delta = append(delta, 0x2c) // src size
	delta = append(delta, 0x2e) // target size
	// Copy cmd: 0x80 | 0x10 (len byte 0) | 0x01 (offset byte 0) -> 0x91
	delta = append(delta, 0x91, 0x00, 0x23) // offset 0, len 35
	// Insert cmd: 11 bytes
	delta = append(delta, 0x0b)
	delta = append(delta, []byte("sleepy cat.")...)

	target, err := applyDelta(base, delta)
	if err != nil {
		t.Fatalf("applyDelta failed: %v", err)
	}

	expected := "The quick brown fox jumps over the sleepy cat."
	if string(target) != expected {
		t.Errorf("expected %q, got %q", expected, string(target))
	}
}

func TestParseCommitObject(t *testing.T) {
	commitData := []byte("tree d8329fc1cc938780ffdd9f94e0d364e0ea74f579\nparent 7f83b1657ff1fc5354dc1008ecf50686d3c52b78\nparent a94a8fe5ccb19ba61c4c0873d391e987982fbbd3\nauthor Test User <test@example.com> 1700000000 +0000\ncommitter Test User <test@example.com> 1700000000 +0000\n\nMerge branch 'feature'\n")
	info := ParseCommitObject("commit-123", commitData)

	if info.Tree != "d8329fc1cc938780ffdd9f94e0d364e0ea74f579" {
		t.Errorf("unexpected tree: %s", info.Tree)
	}
	if len(info.Parents) != 2 {
		t.Fatalf("expected 2 parents, got %d", len(info.Parents))
	}
	if info.Parents[0] != "7f83b1657ff1fc5354dc1008ecf50686d3c52b78" || info.Parents[1] != "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" {
		t.Errorf("unexpected parents: %v", info.Parents)
	}
	if info.Message != "Merge branch 'feature'\n" {
		t.Errorf("unexpected message: %q", info.Message)
	}
}
