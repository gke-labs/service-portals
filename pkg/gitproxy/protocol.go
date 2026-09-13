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
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var (
	// Matches loose git objects: /objects/xx/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	looseObjectRegex = regexp.MustCompile(`/objects/[0-9a-fA-F]{2}/[0-9a-fA-F]{38,62}$`)

	// Matches packfiles and index files: /objects/pack/pack-[0-9a-fA-F]+.(pack|idx)$
	packfileRegex = regexp.MustCompile(`/objects/pack/pack-[0-9a-fA-F]+\.(pack|idx)$`)

	// Matches Git LFS object downloads: /info/lfs/objects/[0-9a-fA-F]{64}$
	lfsObjectRegex = regexp.MustCompile(`/info/lfs/objects/[0-9a-fA-F]{64}$`)
)

// RequestType represents the classified type of a Git HTTP request.
type RequestType int

const (
	RequestTypeOther RequestType = iota
	RequestTypeRefs
	RequestTypeUploadPackFetch
	RequestTypeUploadPackLsRefs
	RequestTypeObject
	RequestTypeReceivePack
)

// ClassifyGitRequest classifies an incoming Git request into a RequestType.
func ClassifyGitRequest(r *http.Request, body []byte) RequestType {
	path := strings.TrimRight(r.URL.Path, "/")

	// Check for Push operations
	if strings.HasSuffix(path, "/git-receive-pack") || (strings.HasSuffix(path, "/info/refs") && r.URL.Query().Get("service") == "git-receive-pack") {
		return RequestTypeReceivePack
	}

	// Check for Ref discovery (Smart or Dumb HTTP)
	if strings.HasSuffix(path, "/info/refs") || strings.HasSuffix(path, "/HEAD") {
		return RequestTypeRefs
	}

	// Check for Smart HTTP upload-pack (git-upload-pack)
	if strings.HasSuffix(path, "/git-upload-pack") {
		if r.Method == http.MethodPost {
			if HasLsRefsCommand(body) {
				return RequestTypeUploadPackLsRefs
			}
			if HasFetchCommand(body) {
				return RequestTypeUploadPackFetch
			}
		}
		// Default to non-cacheable if unknown upload-pack request
		return RequestTypeOther
	}

	// Check for content-addressed objects and packfiles
	if r.Method == http.MethodGet {
		if looseObjectRegex.MatchString(path) || packfileRegex.MatchString(path) || lfsObjectRegex.MatchString(path) {
			return RequestTypeObject
		}
	}

	return RequestTypeOther
}

// IsCacheable returns true if the given request type is content-addressed and safe to cache.
func (rt RequestType) IsCacheable() bool {
	switch rt {
	case RequestTypeUploadPackFetch, RequestTypeObject:
		return true
	default:
		return false
	}
}

// HasLsRefsCommand parses pkt-lines in body to determine if this is a Git protocol v2 ls-refs command.
func HasLsRefsCommand(body []byte) bool {
	lines := parsePktLines(body)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "command=ls-refs" {
			return true
		}
		if strings.HasPrefix(trimmed, "command=") && trimmed != "command=ls-refs" {
			return false
		}
	}
	return false
}

// HasFetchCommand parses pkt-lines or body to determine if this is a fetch / packfile negotiation request.
func HasFetchCommand(body []byte) bool {
	lines := parsePktLines(body)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "command=fetch" || strings.HasPrefix(trimmed, "want ") {
			return true
		}
	}
	// Also fallback to byte search if pkt-line framing is absent or raw
	if bytes.Contains(body, []byte("command=fetch")) || bytes.Contains(body, []byte("want ")) {
		return true
	}
	return false
}

// parsePktLines parses Git pkt-line formatted data into string slices.
func parsePktLines(data []byte) []string {
	var lines []string
	pos := 0
	for pos+4 <= len(data) {
		lenHex := string(data[pos : pos+4])
		length, err := strconv.ParseInt(lenHex, 16, 32)
		if err != nil {
			break
		}

		if length == 0 {
			// Flush packet
			pos += 4
			continue
		} else if length == 1 {
			// Delim packet (v2)
			pos += 4
			continue
		} else if length == 2 {
			// Response-end packet (v2)
			pos += 4
			continue
		}

		if int(length) < 4 || pos+int(length) > len(data) {
			break
		}

		line := string(data[pos+4 : pos+int(length)])
		lines = append(lines, line)
		pos += int(length)
	}
	return lines
}

// FetchRequest represents parsed parameters from a git-upload-pack fetch request.
type FetchRequest struct {
	Wants []string
	Haves []string
	IsV2  bool
	Done  bool
}

// ParseFetchRequest parses wants, haves, and protocol version from a git-upload-pack request body,
// strictly rejecting unrecognized commands, arguments, or capabilities.
func ParseFetchRequest(body []byte) (*FetchRequest, error) {
	lines := parsePktLines(body)
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty fetch request")
	}

	req := &FetchRequest{}
	wantSet := make(map[string]bool)
	haveSet := make(map[string]bool)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if trimmed == "command=fetch" {
			req.IsV2 = true
		} else if strings.HasPrefix(trimmed, "want ") {
			fields := strings.Fields(trimmed[5:])
			if len(fields) == 0 || !isHexOID(fields[0]) {
				return nil, fmt.Errorf("invalid want line format: %q", line)
			}
			oid := fields[0]
			if !wantSet[oid] {
				wantSet[oid] = true
				req.Wants = append(req.Wants, oid)
			}
			// In protocol v0/v1, capabilities may follow on the first want line
			for _, cap := range fields[1:] {
				if !isRecognizedCapability(cap) {
					return nil, fmt.Errorf("unrecognized or unsupported capability: %q", cap)
				}
			}
		} else if strings.HasPrefix(trimmed, "have ") {
			fields := strings.Fields(trimmed[5:])
			if len(fields) == 0 || !isHexOID(fields[0]) {
				return nil, fmt.Errorf("invalid have line format: %q", line)
			}
			oid := fields[0]
			if !haveSet[oid] {
				haveSet[oid] = true
				req.Haves = append(req.Haves, oid)
			}
		} else if trimmed == "done" {
			req.Done = true
		} else if isRecognizedV2Argument(trimmed) {
			continue
		} else {
			return nil, fmt.Errorf("unrecognized or unsupported fetch request line: %q", line)
		}
	}

	if len(req.Wants) == 0 {
		return nil, fmt.Errorf("fetch request contains no valid want lines")
	}

	return req, nil
}

func isHexOID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isRecognizedCapability(cap string) bool {
	switch cap {
	case "multi_ack", "multi_ack_detailed", "no-done",
		"side-band", "side-band-64k", "thin-pack", "ofs-delta",
		"no-progress", "include-tag":
		return true
	}
	if strings.HasPrefix(cap, "agent=") ||
		strings.HasPrefix(cap, "object-format=") ||
		strings.HasPrefix(cap, "session-id=") ||
		strings.HasPrefix(cap, "symref=") ||
		strings.HasPrefix(cap, "clnt-os=") ||
		strings.HasPrefix(cap, "clnt-version=") {
		return true
	}
	return false
}

func isRecognizedV2Argument(arg string) bool {
	switch arg {
	case "thin-pack", "no-progress", "include-tag", "ofs-delta", "sideband-all", "wait-for-done":
		return true
	}
	if strings.HasPrefix(arg, "agent=") ||
		strings.HasPrefix(arg, "object-format=") ||
		strings.HasPrefix(arg, "session-id=") {
		return true
	}
	return false
}

// BuildUpstreamFetchRequest constructs a git-upload-pack fetch request body for upstream.
func BuildUpstreamFetchRequest(wants []string, haves []string, isV2 bool) []byte {
	var buf bytes.Buffer
	if isV2 {
		writePktLineString(&buf, "command=fetch\n")
		writePktLineString(&buf, "agent=gitproxy\n")
		writeDelimPkt(&buf)
		writePktLineString(&buf, "thin-pack\n")
		writePktLineString(&buf, "ofs-delta\n")
		for _, want := range wants {
			writePktLineString(&buf, "want "+want+"\n")
		}
		for _, have := range haves {
			writePktLineString(&buf, "have "+have+"\n")
		}
		writePktLineString(&buf, "done\n")
		writeFlushPkt(&buf)
	} else {
		for i, want := range wants {
			if i == 0 {
				writePktLineString(&buf, "want "+want+" multi_ack_detailed side-band-64k ofs-delta\n")
			} else {
				writePktLineString(&buf, "want "+want+"\n")
			}
		}
		writeFlushPkt(&buf)
		for _, have := range haves {
			writePktLineString(&buf, "have "+have+"\n")
		}
		writePktLineString(&buf, "done\n")
	}
	return buf.Bytes()
}
