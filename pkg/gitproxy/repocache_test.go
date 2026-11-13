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
	"fmt"
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

func TestRepoStoreCompressedResidentMemory(t *testing.T) {
	const n = 10
	const m = 20000 // 20 KB per object, highly compressible

	store := NewRepoStore("")

	var rawObjects []*RawObject
	var treeBuf []byte
	originalBlobs := make(map[string][]byte)

	for i := 0; i < n; i++ {
		content := bytes.Repeat([]byte(fmt.Sprintf("object-%03d-compressible-data-stream-", i)), m/35)
		blobOID := ComputeOID(ObjBlob, content)
		originalBlobs[blobOID] = content

		blob := &RawObject{
			Type: ObjBlob,
			Data: content,
			OID:  blobOID,
		}
		rawObjects = append(rawObjects, blob)

		binaryOID, err := hexDecode(blobOID)
		if err != nil {
			t.Fatalf("failed to decode OID %s: %v", blobOID, err)
		}
		treeBuf = append(treeBuf, []byte(fmt.Sprintf("100644 file-%03d.txt\x00", i))...)
		treeBuf = append(treeBuf, binaryOID...)
	}

	treeOID := ComputeOID(ObjTree, treeBuf)
	tree := &RawObject{
		Type: ObjTree,
		Data: treeBuf,
		OID:  treeOID,
	}
	rawObjects = append(rawObjects, tree)

	commitData := []byte(fmt.Sprintf("tree %s\nauthor Dev <dev@example.com> 1700000000 +0000\ncommitter Dev <dev@example.com> 1700000000 +0000\n\nN objects commit\n", treeOID))
	commitOID := ComputeOID(ObjCommit, commitData)
	commit := &RawObject{
		Type: ObjCommit,
		Data: commitData,
		OID:  commitOID,
	}
	rawObjects = append(rawObjects, commit)

	packData, err := BuildPackfile(rawObjects)
	if err != nil {
		t.Fatalf("BuildPackfile failed: %v", err)
	}

	ingested, err := store.IngestPackfile(packData)
	if err != nil {
		t.Fatalf("IngestPackfile failed: %v", err)
	}
	if len(ingested) != 1 || ingested[0] != commitOID {
		t.Fatalf("expected commit %s ingested, got %v", commitOID, ingested)
	}

	// Calculate resident store size as sum of stored byte slices in store.objects
	var sumStoredByteSlices int64
	for _, obj := range store.objects {
		if obj.Data != nil {
			sumStoredByteSlices += int64(len(obj.Data))
		}
		if obj.Compressed != nil {
			sumStoredByteSlices += int64(len(obj.Compressed))
		}
	}

	residentBytes := store.ResidentStoreSize()
	if residentBytes != sumStoredByteSlices {
		t.Errorf("store.ResidentStoreSize() = %d, want sum of stored byte slices = %d", residentBytes, sumStoredByteSlices)
	}

	uncompressedTotal := int64(n * m)
	t.Logf("Uncompressed total for N*M: %d bytes, pack size: %d bytes, resident store size: %d bytes",
		uncompressedTotal, len(packData), residentBytes)

	// Resident store size must be close to compressed pack size, NOT proportional to uncompressed N*M
	if residentBytes > int64(len(packData)) {
		t.Errorf("resident store size %d exceeded compressed pack size %d", residentBytes, len(packData))
	}
	if residentBytes > uncompressedTotal/10 {
		t.Errorf("resident store size %d is not compressed (expected < %d bytes)", residentBytes, uncompressedTotal/10)
	}

	// Verify that objects can be collected and built into a packfile
	collected, acks, err := store.CollectObjectsForCommits([]string{commitOID}, nil)
	if err != nil {
		t.Fatalf("CollectObjectsForCommits failed: %v", err)
	}
	if len(acks) != 0 {
		t.Errorf("expected 0 acks, got %v", acks)
	}
	if len(collected) != len(rawObjects) {
		t.Fatalf("expected %d collected objects, got %d", len(rawObjects), len(collected))
	}

	servedPack, err := BuildPackfile(collected)
	if err != nil {
		t.Fatalf("BuildPackfile from collected objects failed: %v", err)
	}

	parsedServed, err := ParsePackfile(servedPack)
	if err != nil {
		t.Fatalf("ParsePackfile on served pack failed: %v", err)
	}

	for _, parsed := range parsedServed {
		if expectedContent, ok := originalBlobs[parsed.OID]; ok {
			if !bytes.Equal(parsed.Data, expectedContent) {
				t.Errorf("payload mismatch for object %s", parsed.OID)
			}
		}
	}
}

func TestRepoStoreOnDemandReachabilityMemo(t *testing.T) {
	store := NewRepoStore("")

	// Create a chain of 80 commits
	const numCommits = 80
	var commitOIDs []string

	blobData := []byte("shared content")
	blobOID := ComputeOID(ObjBlob, blobData)
	store.objects[blobOID] = &RawObject{Type: ObjBlob, Data: blobData, OID: blobOID}

	var prevCommit string
	for i := 0; i < numCommits; i++ {
		var treeBuf []byte
		treeBuf = append(treeBuf, []byte(fmt.Sprintf("100644 file-%03d.txt\x00", i))...)
		binBlob, _ := hexDecode(blobOID)
		treeBuf = append(treeBuf, binBlob...)
		treeOID := ComputeOID(ObjTree, treeBuf)
		store.objects[treeOID] = &RawObject{Type: ObjTree, Data: treeBuf, OID: treeOID}
		store.treeEntries[treeOID] = []string{blobOID}

		var commitData []byte
		if prevCommit == "" {
			commitData = []byte(fmt.Sprintf("tree %s\nauthor C <c@example.com> 1700000000 +0000\ncommitter C <c@example.com> 1700000000 +0000\n\nCommit %d\n", treeOID, i))
		} else {
			commitData = []byte(fmt.Sprintf("tree %s\nparent %s\nauthor C <c@example.com> 1700000000 +0000\ncommitter C <c@example.com> 1700000000 +0000\n\nCommit %d\n", treeOID, prevCommit, i))
		}
		commitOID := ComputeOID(ObjCommit, commitData)
		commitObj := &RawObject{Type: ObjCommit, Data: commitData, OID: commitOID}
		store.objects[commitOID] = commitObj

		info := ParseCommitObject(commitOID, commitData)
		store.commits[commitOID] = info
		commitOIDs = append(commitOIDs, commitOID)
		prevCommit = commitOID
	}

	// Verify that before any CollectObjectsForCommits, the memo commitObjects is empty
	if len(store.commitObjects) != 0 {
		t.Errorf("expected empty commitObjects memo before queries, got %d", len(store.commitObjects))
	}

	// Query each commit's reachable objects
	for _, cOID := range commitOIDs {
		objs := store.getReachableObjects(cOID)
		if len(objs) < 2 { // at least commit + tree + blob
			t.Errorf("expected reachable objects for commit %s, got %v", cOID, objs)
		}
	}

	// Memo must be bounded to maxMemoEntries (64)
	if len(store.commitObjects) > 64 {
		t.Errorf("commitObjects memo exceeded capacity: %d > 64", len(store.commitObjects))
	}
	if len(store.commitObjects) != 64 {
		t.Errorf("expected memo to be at capacity 64, got %d", len(store.commitObjects))
	}

	// Verify that queries on recent commits hit the memo
	lastCommit := commitOIDs[len(commitOIDs)-1]
	if _, ok := store.commitObjects[lastCommit]; !ok {
		t.Errorf("expected recent commit %s to be present in memo", lastCommit)
	}

	// Earliest commits should have been evicted
	firstCommit := commitOIDs[0]
	if _, ok := store.commitObjects[firstCommit]; ok {
		t.Errorf("expected earliest commit %s to have been evicted from memo", firstCommit)
	}
}
