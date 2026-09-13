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
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Object types in Git packfiles.
const (
	ObjCommit   = 1
	ObjTree     = 2
	ObjBlob     = 3
	ObjTag      = 4
	ObjOfsDelta = 6
	ObjRefDelta = 7
)

// RawObject represents a decompressed, whole Git object.
type RawObject struct {
	Type int    // ObjCommit, ObjTree, ObjBlob, ObjTag
	Data []byte // Uncompressed payload
	OID  string // 40-character hex SHA-1
}

// ComputeOID computes the Git Object ID (SHA-1) for a given object type and uncompressed data.
func ComputeOID(objType int, data []byte) string {
	typeName := TypeToString(objType)
	header := fmt.Sprintf("%s %d\x00", typeName, len(data))
	h := sha1.New()
	h.Write([]byte(header))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// TypeToString returns the string representation of a Git object type.
func TypeToString(t int) string {
	switch t {
	case ObjCommit:
		return "commit"
	case ObjTree:
		return "tree"
	case ObjBlob:
		return "blob"
	case ObjTag:
		return "tag"
	default:
		return "unknown"
	}
}

// StringToType converts a Git object type string to its numeric type.
func StringToType(s string) int {
	switch s {
	case "commit":
		return ObjCommit
	case "tree":
		return ObjTree
	case "blob":
		return ObjBlob
	case "tag":
		return ObjTag
	default:
		return 0
	}
}

// CommitInfo holds parsed metadata from an ObjCommit object.
type CommitInfo struct {
	OID     string
	Tree    string
	Parents []string
	Author  string
	Message string
}

// ParseCommitObject parses the header and metadata from a commit object's data.
func ParseCommitObject(oid string, data []byte) *CommitInfo {
	info := &CommitInfo{
		OID: oid,
	}

	content := string(data)
	parts := strings.SplitN(content, "\n\n", 2)
	headerLines := strings.Split(parts[0], "\n")
	if len(parts) > 1 {
		info.Message = parts[1]
	}

	for _, line := range headerLines {
		if strings.HasPrefix(line, "tree ") {
			info.Tree = strings.TrimSpace(strings.TrimPrefix(line, "tree "))
		} else if strings.HasPrefix(line, "parent ") {
			parent := strings.TrimSpace(strings.TrimPrefix(line, "parent "))
			if parent != "" {
				info.Parents = append(info.Parents, parent)
			}
		} else if strings.HasPrefix(line, "author ") {
			info.Author = strings.TrimSpace(strings.TrimPrefix(line, "author "))
		}
	}

	return info
}

// ParseTreeEntries extracts all referenced OIDs from a tree object's data.
func ParseTreeEntries(data []byte) ([]string, error) {
	var oids []string
	pos := 0
	for pos < len(data) {
		nullIdx := bytes.IndexByte(data[pos:], 0)
		if nullIdx == -1 {
			break
		}
		pos += nullIdx + 1
		if pos+20 > len(data) {
			break
		}
		entryOID := hex.EncodeToString(data[pos : pos+20])
		oids = append(oids, entryOID)
		pos += 20
	}
	return oids, nil
}

type countingByteReader struct {
	data  []byte
	pos   int
	count int
}

func (r *countingByteReader) ReadByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	b := r.data[r.pos]
	r.pos++
	r.count++
	return b, nil
}

func (r *countingByteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	r.count += n
	return n, nil
}

type rawPackEntry struct {
	objType        int
	uncompressedSz uint64
	offset         int
	baseOffset     int    // for OBJ_OFS_DELTA
	baseOID        string // for OBJ_REF_DELTA
	decompressed   []byte
}

// ParsePackfile parses a raw Git packfile and resolves all deltas into whole RawObjects.
func ParsePackfile(data []byte) ([]*RawObject, error) {
	return ParsePackfileWithBase(data, nil)
}

// ParsePackfileWithBase parses a raw Git packfile and resolves deltas, optionally looking up bases from an external store.
func ParsePackfileWithBase(data []byte, baseLookup func(oid string) *RawObject) ([]*RawObject, error) {
	if len(data) < 12+20 {
		return nil, fmt.Errorf("packfile too short: %d bytes", len(data))
	}

	if !bytes.Equal(data[:4], []byte("PACK")) {
		return nil, fmt.Errorf("invalid packfile signature: %q", string(data[:4]))
	}

	version := binary.BigEndian.Uint32(data[4:8])
	if version != 2 && version != 3 {
		return nil, fmt.Errorf("unsupported packfile version: %d", version)
	}

	numObjects := binary.BigEndian.Uint32(data[8:12])
	pos := 12

	entries := make([]*rawPackEntry, 0, numObjects)
	offsetMap := make(map[int]*rawPackEntry)

	for i := uint32(0); i < numObjects; i++ {
		if pos >= len(data)-20 {
			return nil, fmt.Errorf("unexpected end of packfile at object %d/%d", i, numObjects)
		}

		entryOffset := pos
		b := data[pos]
		pos++

		objType := int((b >> 4) & 0x07)
		size := uint64(b & 0x0f)
		shift := 4

		for (b & 0x80) != 0 {
			if pos >= len(data)-20 {
				return nil, fmt.Errorf("truncated object header at offset %d", entryOffset)
			}
			b = data[pos]
			pos++
			size |= uint64(b&0x7f) << shift
			shift += 7
		}

		entry := &rawPackEntry{
			objType:        objType,
			uncompressedSz: size,
			offset:         entryOffset,
		}

		if objType == ObjOfsDelta {
			if pos >= len(data)-20 {
				return nil, fmt.Errorf("truncated ofs-delta header at offset %d", entryOffset)
			}
			b = data[pos]
			pos++
			ofs := uint64(b & 0x7f)
			for (b & 0x80) != 0 {
				if pos >= len(data)-20 {
					return nil, fmt.Errorf("truncated ofs-delta offset at offset %d", entryOffset)
				}
				b = data[pos]
				pos++
				ofs = ((ofs + 1) << 7) | uint64(b&0x7f)
			}
			entry.baseOffset = entryOffset - int(ofs)
		} else if objType == ObjRefDelta {
			if pos+20 > len(data)-20 {
				return nil, fmt.Errorf("truncated ref-delta base oid at offset %d", entryOffset)
			}
			entry.baseOID = hex.EncodeToString(data[pos : pos+20])
			pos += 20
		}

		cbr := &countingByteReader{
			data: data,
			pos:  pos,
		}

		zr, err := zlib.NewReader(cbr)
		if err != nil {
			return nil, fmt.Errorf("failed to create zlib reader at offset %d: %w", entryOffset, err)
		}

		decompressed := make([]byte, size)
		if _, err := io.ReadFull(zr, decompressed); err != nil {
			zr.Close()
			return nil, fmt.Errorf("failed to decompress object data at offset %d (type %d, expected %d bytes): %w", entryOffset, objType, size, err)
		}
		zr.Close()

		pos += cbr.count
		entry.decompressed = decompressed
		entries = append(entries, entry)
		offsetMap[entryOffset] = entry
	}

	// Resolve deltas into whole objects
	resolvedObjects := make(map[string]*RawObject)
	resolvedByOffset := make(map[int]*RawObject)

	// First pass: register non-delta objects
	for _, entry := range entries {
		if entry.objType != ObjOfsDelta && entry.objType != ObjRefDelta {
			oid := ComputeOID(entry.objType, entry.decompressed)
			obj := &RawObject{
				Type: entry.objType,
				Data: entry.decompressed,
				OID:  oid,
			}
			resolvedObjects[oid] = obj
			resolvedByOffset[entry.offset] = obj
		}
	}

	// Multi-pass resolution for deltas
	maxPasses := 50
	for pass := 0; pass < maxPasses; pass++ {
		progress := false
		for _, entry := range entries {
			if entry.objType == ObjOfsDelta {
				if _, done := resolvedByOffset[entry.offset]; done {
					continue
				}
				baseObj, ok := resolvedByOffset[entry.baseOffset]
				if !ok {
					continue
				}
				applied, err := applyDelta(baseObj.Data, entry.decompressed)
				if err != nil {
					return nil, fmt.Errorf("failed to apply ofs-delta at offset %d: %w", entry.offset, err)
				}
				oid := ComputeOID(baseObj.Type, applied)
				obj := &RawObject{
					Type: baseObj.Type,
					Data: applied,
					OID:  oid,
				}
				resolvedObjects[oid] = obj
				resolvedByOffset[entry.offset] = obj
				progress = true
			} else if entry.objType == ObjRefDelta {
				if _, done := resolvedByOffset[entry.offset]; done {
					continue
				}
				baseObj, ok := resolvedObjects[entry.baseOID]
				if !ok && baseLookup != nil {
					baseObj = baseLookup(entry.baseOID)
					if baseObj != nil {
						ok = true
					}
				}
				if !ok {
					continue
				}
				applied, err := applyDelta(baseObj.Data, entry.decompressed)
				if err != nil {
					return nil, fmt.Errorf("failed to apply ref-delta at offset %d on base %s: %w", entry.offset, entry.baseOID, err)
				}
				oid := ComputeOID(baseObj.Type, applied)
				obj := &RawObject{
					Type: baseObj.Type,
					Data: applied,
					OID:  oid,
				}
				resolvedObjects[oid] = obj
				resolvedByOffset[entry.offset] = obj
				progress = true
			}
		}
		if len(resolvedByOffset) == len(entries) {
			break
		}
		if !progress {
			break
		}
	}

	if len(resolvedByOffset) < len(entries) {
		return nil, fmt.Errorf("could not resolve all deltas (%d resolved out of %d)", len(resolvedByOffset), len(entries))
	}

	result := make([]*RawObject, 0, len(entries))
	for _, entry := range entries {
		result = append(result, resolvedByOffset[entry.offset])
	}

	return result, nil
}

// applyDelta applies a Git pack delta to a base object payload.
func applyDelta(base []byte, delta []byte) ([]byte, error) {
	if len(delta) == 0 {
		return nil, fmt.Errorf("empty delta")
	}

	// Read source size
	srcSize, n := readLEB128(delta)
	if n <= 0 {
		return nil, fmt.Errorf("invalid delta src size")
	}
	delta = delta[n:]
	if int(srcSize) != len(base) {
		return nil, fmt.Errorf("delta base size mismatch: expected %d, got %d", srcSize, len(base))
	}

	// Read target size
	targetSize, n := readLEB128(delta)
	if n <= 0 {
		return nil, fmt.Errorf("invalid delta target size")
	}
	delta = delta[n:]

	target := make([]byte, targetSize)
	targetPos := 0

	for len(delta) > 0 {
		cmd := delta[0]
		delta = delta[1:]

		if (cmd & 0x80) != 0 {
			// Copy command
			var offset uint32
			var length uint32

			if (cmd & 0x01) != 0 {
				if len(delta) == 0 {
					return nil, fmt.Errorf("unexpected end of delta in copy offset byte 0")
				}
				offset |= uint32(delta[0])
				delta = delta[1:]
			}
			if (cmd & 0x02) != 0 {
				if len(delta) == 0 {
					return nil, fmt.Errorf("unexpected end of delta in copy offset byte 1")
				}
				offset |= uint32(delta[0]) << 8
				delta = delta[1:]
			}
			if (cmd & 0x04) != 0 {
				if len(delta) == 0 {
					return nil, fmt.Errorf("unexpected end of delta in copy offset byte 2")
				}
				offset |= uint32(delta[0]) << 16
				delta = delta[1:]
			}
			if (cmd & 0x08) != 0 {
				if len(delta) == 0 {
					return nil, fmt.Errorf("unexpected end of delta in copy offset byte 3")
				}
				offset |= uint32(delta[0]) << 24
				delta = delta[1:]
			}

			if (cmd & 0x10) != 0 {
				if len(delta) == 0 {
					return nil, fmt.Errorf("unexpected end of delta in copy len byte 0")
				}
				length |= uint32(delta[0])
				delta = delta[1:]
			}
			if (cmd & 0x20) != 0 {
				if len(delta) == 0 {
					return nil, fmt.Errorf("unexpected end of delta in copy len byte 1")
				}
				length |= uint32(delta[0]) << 8
				delta = delta[1:]
			}
			if (cmd & 0x40) != 0 {
				if len(delta) == 0 {
					return nil, fmt.Errorf("unexpected end of delta in copy len byte 2")
				}
				length |= uint32(delta[0]) << 16
				delta = delta[1:]
			}

			if length == 0 {
				length = 0x10000 // 65536
			}

			if int(offset+length) > len(base) || targetPos+int(length) > len(target) {
				return nil, fmt.Errorf("delta copy out of bounds: offset=%d len=%d baseLen=%d targetLen=%d targetPos=%d",
					offset, length, len(base), len(target), targetPos)
			}

			copy(target[targetPos:targetPos+int(length)], base[offset:offset+length])
			targetPos += int(length)
		} else if cmd > 0 {
			// Insert command
			length := int(cmd)
			if length > len(delta) || targetPos+length > len(target) {
				return nil, fmt.Errorf("delta insert out of bounds: len=%d deltaLen=%d targetPos=%d targetLen=%d",
					length, len(delta), targetPos, len(target))
			}
			copy(target[targetPos:targetPos+length], delta[:length])
			delta = delta[length:]
			targetPos += length
		} else {
			return nil, fmt.Errorf("invalid delta opcode 0")
		}
	}

	if targetPos != int(targetSize) {
		return nil, fmt.Errorf("delta target size mismatch: generated %d, expected %d", targetPos, targetSize)
	}

	return target, nil
}

func readLEB128(data []byte) (uint64, int) {
	var val uint64
	var shift uint
	for i, b := range data {
		val |= uint64(b&0x7f) << shift
		shift += 7
		if (b & 0x80) == 0 {
			return val, i + 1
		}
		if shift >= 64 {
			return 0, 0
		}
	}
	return 0, 0
}

// BuildPackfile builds a standard Git packfile containing the provided whole objects.
func BuildPackfile(objects []*RawObject) ([]byte, error) {
	var buf bytes.Buffer

	// 12-byte header: "PACK", version 2, numObjects
	buf.WriteString("PACK")
	binary.Write(&buf, binary.BigEndian, uint32(2))
	binary.Write(&buf, binary.BigEndian, uint32(len(objects)))

	hasher := sha1.New()
	hasher.Write(buf.Bytes())

	for _, obj := range objects {
		var objHeader bytes.Buffer
		size := uint64(len(obj.Data))
		b := byte(obj.Type<<4) | byte(size&0x0f)
		size >>= 4
		if size > 0 {
			b |= 0x80
		}
		objHeader.WriteByte(b)
		for size > 0 {
			b = byte(size & 0x7f)
			size >>= 7
			if size > 0 {
				b |= 0x80
			}
			objHeader.WriteByte(b)
		}

		headerBytes := objHeader.Bytes()
		buf.Write(headerBytes)
		hasher.Write(headerBytes)

		// Deflate object data
		var compressedBuf bytes.Buffer
		zw := zlib.NewWriter(&compressedBuf)
		if _, err := zw.Write(obj.Data); err != nil {
			return nil, fmt.Errorf("failed to compress object %s: %w", obj.OID, err)
		}
		if err := zw.Close(); err != nil {
			return nil, fmt.Errorf("failed to close zlib writer for object %s: %w", obj.OID, err)
		}

		compBytes := compressedBuf.Bytes()
		buf.Write(compBytes)
		hasher.Write(compBytes)
	}

	// 20-byte SHA-1 trailer
	checksum := hasher.Sum(nil)
	buf.Write(checksum)

	return buf.Bytes(), nil
}

// ExtractPackfileFromResponse extracts the raw packfile stream from a Git upload-pack response body.
func ExtractPackfileFromResponse(respBody []byte) ([]byte, error) {
	// First check if response is already raw PACK bytes
	if bytes.HasPrefix(respBody, []byte("PACK")) {
		return respBody, nil
	}

	var packBuf bytes.Buffer
	pos := 0

	for pos+4 <= len(respBody) {
		lenHex := string(respBody[pos : pos+4])
		length, err := hex.DecodeString(lenHex)
		if err != nil || len(length) != 2 {
			break
		}
		pktLen := int(binary.BigEndian.Uint16(length))
		if pktLen == 0 {
			// Flush packet
			pos += 4
			continue
		} else if pktLen == 1 || pktLen == 2 {
			// Delim or response-end
			pos += 4
			continue
		}

		if pktLen < 4 || pos+pktLen > len(respBody) {
			break
		}

		packet := respBody[pos+4 : pos+pktLen]
		if len(packet) > 0 {
			band := packet[0]
			if band == 1 {
				// Sideband channel 1: Pack data
				packBuf.Write(packet[1:])
			}
		}
		pos += pktLen
	}

	if packBuf.Len() > 0 {
		return packBuf.Bytes(), nil
	}

	// Fallback: search for "PACK" in response body
	if idx := bytes.Index(respBody, []byte("PACK")); idx != -1 {
		return respBody[idx:], nil
	}

	return nil, fmt.Errorf("no packfile found in upload-pack response")
}

// FormatSidebandPackfile formats a packfile into sideband pkt-lines for Git protocol v0/v1 or v2.
func FormatSidebandPackfile(packfile []byte, isV2 bool, acks []string, hasHaves bool) []byte {
	var buf bytes.Buffer

	if isV2 {
		// Protocol v2 header
		if hasHaves {
			writePktLineString(&buf, "acknowledgments\n")
			for _, ack := range acks {
				writePktLineString(&buf, fmt.Sprintf("ACK %s\n", ack))
			}
			if len(acks) == 0 {
				writePktLineString(&buf, "NAK\n")
			}
			writePktLineString(&buf, "ready\n")
			writeDelimPkt(&buf)
		}
		writePktLineString(&buf, "packfile\n")
	} else {
		// Protocol v0/v1 header
		if len(acks) > 0 {
			for _, ack := range acks {
				writePktLineString(&buf, fmt.Sprintf("ACK %s common\n", ack))
			}
		} else {
			writePktLineString(&buf, "NAK\n")
		}
	}

	// Stream packfile in 65515-byte chunks (band 1)
	const maxChunk = 65515
	for pos := 0; pos < len(packfile); pos += maxChunk {
		end := pos + maxChunk
		if end > len(packfile) {
			end = len(packfile)
		}
		chunk := packfile[pos:end]
		pktLen := len(chunk) + 5 // 4 bytes len + 1 byte band
		fmt.Fprintf(&buf, "%04x\x01", pktLen)
		buf.Write(chunk)
	}

	// Flush
	writeFlushPkt(&buf)

	return buf.Bytes()
}

func writePktLineString(buf *bytes.Buffer, s string) {
	pktLen := len(s) + 4
	fmt.Fprintf(buf, "%04x%s", pktLen, s)
}

func writeFlushPkt(buf *bytes.Buffer) {
	buf.WriteString("0000")
}

func writeDelimPkt(buf *bytes.Buffer) {
	buf.WriteString("0001")
}
