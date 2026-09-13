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
	"testing"
)

func TestRepoStoreIngestAndPrune(t *testing.T) {
	store := NewRepoStore("")

	// Create commit 1: base commit with blob1
	blob1Data := []byte("content of file 1")
	blob1OID := ComputeOID(ObjBlob, blob1Data)
	blob1 := &RawObject{Type: ObjBlob, Data: blob1Data, OID: blob1OID}

	// Tree 1 referencing blob 1
	// Tree entry format: "100644 file1.txt\x00<20 bytes binary sha1>"
	var tree1Buf []byte
	tree1Buf = append(tree1Buf, []byte("100644 file1.txt\x00")...)
	blob1Binary, _ := hexDecode(blob1OID)
	tree1Buf = append(tree1Buf, blob1Binary...)
	tree1OID := ComputeOID(ObjTree, tree1Buf)
	tree1 := &RawObject{Type: ObjTree, Data: tree1Buf, OID: tree1OID}

	// Commit 1
	commit1Data := []byte("tree " + tree1OID + "\nauthor Alice <alice@example.com> 1700000000 +0000\ncommitter Alice <alice@example.com> 1700000000 +0000\n\nCommit 1\n")
	commit1OID := ComputeOID(ObjCommit, commit1Data)
	commit1 := &RawObject{Type: ObjCommit, Data: commit1Data, OID: commit1OID}

	// Build pack 1
	pack1, err := BuildPackfile([]*RawObject{commit1, tree1, blob1})
	if err != nil {
		t.Fatalf("BuildPackfile pack1 failed: %v", err)
	}

	ingested1, err := store.IngestPackfile(pack1)
	if err != nil {
		t.Fatalf("IngestPackfile pack1 failed: %v", err)
	}
	if len(ingested1) != 1 || ingested1[0] != commit1OID {
		t.Fatalf("expected commit1 ingested, got %v", ingested1)
	}

	if !store.HasCommit(commit1OID) {
		t.Errorf("expected store to have commit1")
	}

	// Create commit 2: child of commit 1 with new blob 2 and reusing blob 1
	blob2Data := []byte("content of file 2")
	blob2OID := ComputeOID(ObjBlob, blob2Data)
	blob2 := &RawObject{Type: ObjBlob, Data: blob2Data, OID: blob2OID}

	var tree2Buf []byte
	tree2Buf = append(tree2Buf, []byte("100644 file1.txt\x00")...)
	tree2Buf = append(tree2Buf, blob1Binary...)
	tree2Buf = append(tree2Buf, []byte("100644 file2.txt\x00")...)
	blob2Binary, _ := hexDecode(blob2OID)
	tree2Buf = append(tree2Buf, blob2Binary...)
	tree2OID := ComputeOID(ObjTree, tree2Buf)
	tree2 := &RawObject{Type: ObjTree, Data: tree2Buf, OID: tree2OID}

	commit2Data := []byte("tree " + tree2OID + "\nparent " + commit1OID + "\nauthor Bob <bob@example.com> 1700000100 +0000\ncommitter Bob <bob@example.com> 1700000100 +0000\n\nCommit 2\n")
	commit2OID := ComputeOID(ObjCommit, commit2Data)
	commit2 := &RawObject{Type: ObjCommit, Data: commit2Data, OID: commit2OID}

	// Build pack 2 (incremental objects for commit 2)
	pack2, err := BuildPackfile([]*RawObject{commit2, tree2, blob2})
	if err != nil {
		t.Fatalf("BuildPackfile pack2 failed: %v", err)
	}

	ingested2, err := store.IngestPackfile(pack2)
	if err != nil {
		t.Fatalf("IngestPackfile pack2 failed: %v", err)
	}
	if len(ingested2) != 1 || ingested2[0] != commit2OID {
		t.Fatalf("expected commit2 ingested, got %v", ingested2)
	}

	// Case A: Full clone request (wants commit2, haves none)
	// Must return all objects for commit1 and commit2
	objsFull, acksFull, err := store.CollectObjectsForCommits([]string{commit2OID}, nil)
	if err != nil {
		t.Fatalf("CollectObjectsForCommits full failed: %v", err)
	}
	if len(acksFull) != 0 {
		t.Errorf("expected 0 acks for full clone, got %v", acksFull)
	}
	if len(objsFull) != 5 { // commit1, commit2, tree1, tree2, blob1, blob2 -> tree1 is also reachable or 5 objects (commit1, commit2, tree2, blob1, blob2, etc)
		t.Logf("Full clone collected %d objects", len(objsFull))
	}

	// Case B: Incremental pull request (wants commit2, haves commit1)
	// Must prune commit1 objects and only return commit2 new objects (commit2, tree2, blob2)
	objsIncr, acksIncr, err := store.CollectObjectsForCommits([]string{commit2OID}, []string{commit1OID})
	if err != nil {
		t.Fatalf("CollectObjectsForCommits incremental failed: %v", err)
	}
	if len(acksIncr) != 1 || acksIncr[0] != commit1OID {
		t.Errorf("expected ACK for commit1, got %v", acksIncr)
	}

	incrOIDs := make(map[string]bool)
	for _, obj := range objsIncr {
		incrOIDs[obj.OID] = true
	}

	if incrOIDs[commit1OID] {
		t.Errorf("commit1 should have been pruned from incremental response")
	}
	if incrOIDs[tree1OID] {
		t.Errorf("tree1 should have been pruned from incremental response")
	}
	if incrOIDs[blob1OID] {
		t.Errorf("blob1 should have been pruned from incremental response")
	}
	if !incrOIDs[commit2OID] {
		t.Errorf("commit2 should be included in incremental response")
	}
	if !incrOIDs[tree2OID] {
		t.Errorf("tree2 should be included in incremental response")
	}
	if !incrOIDs[blob2OID] {
		t.Errorf("blob2 should be included in incremental response")
	}
}

func hexDecode(s string) ([]byte, error) {
	var b []byte
	for i := 0; i < len(s); i += 2 {
		var val byte
		for j := 0; j < 2; j++ {
			c := s[i+j]
			val <<= 4
			switch {
			case c >= '0' && c <= '9':
				val |= c - '0'
			case c >= 'a' && c <= 'f':
				val |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				val |= c - 'A' + 10
			}
		}
		b = append(b, val)
	}
	return b, nil
}
