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
	"io"
	"math/rand"
	"runtime"
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

func TestEncodeHex4(t *testing.T) {
	var dst [4]byte
	for v := 0; v <= 0xffff; v++ {
		encodeHex4(dst[:], v)
		expected := fmt.Sprintf("%04x", v)
		if string(dst[:]) != expected {
			t.Fatalf("encodeHex4(%d) = %q; want %q", v, string(dst[:]), expected)
		}
	}
}

func TestWritePackfile(t *testing.T) {
	blobData := []byte("Streaming Packfile Test Data\n")
	blobOID := ComputeOID(ObjBlob, blobData)
	blob := &RawObject{
		Type: ObjBlob,
		Data: blobData,
		OID:  blobOID,
	}

	var buf bytes.Buffer
	if err := WritePackfile(&buf, []*RawObject{blob}); err != nil {
		t.Fatalf("WritePackfile failed: %v", err)
	}

	legacyBytes, err := BuildPackfile([]*RawObject{blob})
	if err != nil {
		t.Fatalf("BuildPackfile failed: %v", err)
	}

	if !bytes.Equal(buf.Bytes(), legacyBytes) {
		t.Fatalf("WritePackfile output does not match BuildPackfile output")
	}
}

func TestSidebandWriterMultiChunk(t *testing.T) {
	// Create a random blob larger than maxSidebandPayload (65515 bytes)
	// Random bytes cannot be compressed by DEFLATE below 65515 bytes.
	rng := rand.New(rand.NewSource(42))
	blobData := make([]byte, 80000)
	_, err := rng.Read(blobData)
	if err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}
	blobOID := ComputeOID(ObjBlob, blobData)
	blob := &RawObject{
		Type: ObjBlob,
		Data: blobData,
		OID:  blobOID,
	}

	// 1. Write the packfile through a SidebandWriter
	var framedBuf bytes.Buffer
	sw := NewSidebandWriter(&framedBuf, 1)
	if err := WritePackfile(sw, []*RawObject{blob}); err != nil {
		t.Fatalf("WritePackfile through SidebandWriter failed: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("sw.Close() failed: %v", err)
	}

	// Verify framing details
	framedBytes := framedBuf.Bytes()
	if len(framedBytes) <= 65515 {
		t.Fatalf("expected framed output > 65515 bytes, got %d", len(framedBytes))
	}
	// The first chunk must have max length 65520 (65515 payload + 5 header): "fff0\x01"
	if string(framedBytes[:4]) != "fff0" || framedBytes[4] != 0x01 {
		t.Fatalf("expected first chunk to start with 'fff0\\x01', got %q", string(framedBytes[:5]))
	}
	// The stream must end with the flush pkt "0000"
	if string(framedBytes[len(framedBytes)-4:]) != "0000" {
		t.Fatalf("expected stream to terminate with '0000', got %q", string(framedBytes[len(framedBytes)-4:]))
	}

	// 2. Round-trip: ExtractPackfileFromResponse -> ParsePackfile
	extractedPack, err := ExtractPackfileFromResponse(framedBytes)
	if err != nil {
		t.Fatalf("ExtractPackfileFromResponse failed: %v", err)
	}

	parsedObjects, err := ParsePackfile(extractedPack)
	if err != nil {
		t.Fatalf("ParsePackfile failed: %v", err)
	}
	if len(parsedObjects) != 1 {
		t.Fatalf("expected 1 parsed object, got %d", len(parsedObjects))
	}
	if parsedObjects[0].OID != blobOID {
		t.Fatalf("expected OID %s, got %s", blobOID, parsedObjects[0].OID)
	}
	if !bytes.Equal(parsedObjects[0].Data, blobData) {
		t.Fatalf("parsed object payload does not match original data")
	}
}

func TestPackfileResponseRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(123))
	blobData := make([]byte, 75000)
	_, _ = rng.Read(blobData)
	blobOID := ComputeOID(ObjBlob, blobData)
	blob := &RawObject{
		Type: ObjBlob,
		Data: blobData,
		OID:  blobOID,
	}

	// Test Protocol v2 response
	respV2 := NewPackfileResponse([]*RawObject{blob}, true, []string{"ack-commit"}, true)
	var bufV2 bytes.Buffer
	n2, err := respV2.WriteTo(&bufV2)
	if err != nil {
		t.Fatalf("respV2.WriteTo failed: %v", err)
	}
	if n2 != int64(bufV2.Len()) {
		t.Fatalf("WriteTo returned %d, buffer len is %d", n2, bufV2.Len())
	}

	extractedV2, err := ExtractPackfileFromResponse(bufV2.Bytes())
	if err != nil {
		t.Fatalf("ExtractPackfileFromResponse v2 failed: %v", err)
	}
	parsedV2, err := ParsePackfile(extractedV2)
	if err != nil {
		t.Fatalf("ParsePackfile v2 failed: %v", err)
	}
	if len(parsedV2) != 1 || parsedV2[0].OID != blobOID || !bytes.Equal(parsedV2[0].Data, blobData) {
		t.Fatalf("v2 roundtrip object mismatch")
	}

	// Test Protocol v0/v1 response
	respV1 := NewPackfileResponse([]*RawObject{blob}, false, []string{"ack-commit"}, false)
	var bufV1 bytes.Buffer
	n1, err := respV1.WriteTo(&bufV1)
	if err != nil {
		t.Fatalf("respV1.WriteTo failed: %v", err)
	}
	if n1 != int64(bufV1.Len()) {
		t.Fatalf("WriteTo returned %d, buffer len is %d", n1, bufV1.Len())
	}

	extractedV1, err := ExtractPackfileFromResponse(bufV1.Bytes())
	if err != nil {
		t.Fatalf("ExtractPackfileFromResponse v1 failed: %v", err)
	}
	parsedV1, err := ParsePackfile(extractedV1)
	if err != nil {
		t.Fatalf("ParsePackfile v1 failed: %v", err)
	}
	if len(parsedV1) != 1 || parsedV1[0].OID != blobOID || !bytes.Equal(parsedV1[0].Data, blobData) {
		t.Fatalf("v1 roundtrip object mismatch")
	}
}

func TestSidebandWriterAllocationBound(t *testing.T) {
	// Verify that SidebandWriter allocation count does not scale with payload size P.
	// Write 1 MB vs 10 MB in 32 KB blocks to io.Discard.
	chunk := make([]byte, 32*1024)

	allocs1MB := testing.AllocsPerRun(10, func() {
		sw := NewSidebandWriter(io.Discard, 1)
		for i := 0; i < 32; i++ { // 32 * 32KB = 1MB
			if _, err := sw.Write(chunk); err != nil {
				t.Fatalf("sw.Write failed: %v", err)
			}
		}
		if err := sw.Close(); err != nil {
			t.Fatalf("sw.Close failed: %v", err)
		}
	})

	allocs10MB := testing.AllocsPerRun(10, func() {
		sw := NewSidebandWriter(io.Discard, 1)
		for i := 0; i < 320; i++ { // 320 * 32KB = 10MB
			if _, err := sw.Write(chunk); err != nil {
				t.Fatalf("sw.Write failed: %v", err)
			}
		}
		if err := sw.Close(); err != nil {
			t.Fatalf("sw.Close failed: %v", err)
		}
	})

	if allocs1MB > 5 || allocs10MB > 5 {
		t.Errorf("expected <= 5 allocations per run, got 1MB: %f, 10MB: %f", allocs1MB, allocs10MB)
	}
	if allocs1MB != allocs10MB {
		t.Errorf("expected constant number of allocations, got 1MB: %f, 10MB: %f", allocs1MB, allocs10MB)
	}

	// Verify using runtime.MemStats that 10 MB stream peak heap allocation is bounded by ~65KB chunk
	runtime.GC()
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)
	sw := NewSidebandWriter(io.Discard, 1)
	for i := 0; i < 320; i++ {
		_, _ = sw.Write(chunk)
	}
	_ = sw.Close()
	runtime.ReadMemStats(&m2)

	allocated := m2.TotalAlloc - m1.TotalAlloc
	// 10 MB stream formatted with SidebandWriter should allocate far less than 150 KB total heap memory
	if allocated > 150*1024 {
		t.Errorf("expected TotalAlloc < 150KB for 10MB stream, got %d bytes", allocated)
	}
}

func BenchmarkSidebandWriter_1MB(b *testing.B) {
	chunk := make([]byte, 32*1024)
	b.SetBytes(1024 * 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sw := NewSidebandWriter(io.Discard, 1)
		for j := 0; j < 32; j++ {
			_, _ = sw.Write(chunk)
		}
		_ = sw.Close()
	}
}

func BenchmarkSidebandWriter_10MB(b *testing.B) {
	chunk := make([]byte, 32*1024)
	b.SetBytes(10 * 1024 * 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sw := NewSidebandWriter(io.Discard, 1)
		for j := 0; j < 320; j++ {
			_, _ = sw.Write(chunk)
		}
		_ = sw.Close()
	}
}

func BenchmarkFormatSidebandPackfile_1MB(b *testing.B) {
	packfile := make([]byte, 1024*1024)
	b.SetBytes(1024 * 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FormatSidebandPackfile(packfile, true, nil, false)
	}
}

func BenchmarkWritePackfile(b *testing.B) {
	blobData := make([]byte, 100000)
	blobOID := ComputeOID(ObjBlob, blobData)
	blob := &RawObject{
		Type: ObjBlob,
		Data: blobData,
		OID:  blobOID,
	}
	b.SetBytes(int64(len(blobData)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = WritePackfile(io.Discard, []*RawObject{blob})
	}
}
