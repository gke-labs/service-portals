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
	"net/http/httptest"
	"testing"
)

func TestClassifyGitRequest(t *testing.T) {
	tests := []struct {
		name              string
		method            string
		path              string
		body              []byte
		expectedType      RequestType
		expectedCacheable bool
	}{
		{
			name:              "Smart HTTP refs discovery",
			method:            http.MethodGet,
			path:              "/org/repo.git/info/refs?service=git-upload-pack",
			expectedType:      RequestTypeRefs,
			expectedCacheable: false,
		},
		{
			name:              "Dumb HTTP refs discovery",
			method:            http.MethodGet,
			path:              "/org/repo.git/info/refs",
			expectedType:      RequestTypeRefs,
			expectedCacheable: false,
		},
		{
			name:              "HEAD ref request",
			method:            http.MethodGet,
			path:              "/org/repo.git/HEAD",
			expectedType:      RequestTypeRefs,
			expectedCacheable: false,
		},
		{
			name:              "Protocol v2 ls-refs",
			method:            http.MethodPost,
			path:              "/org/repo.git/git-upload-pack",
			body:              []byte("0014command=ls-refs\n0014agent=git/2.47.0\n00010009peel\n000csymrefs\n0000"),
			expectedType:      RequestTypeUploadPackLsRefs,
			expectedCacheable: false,
		},
		{
			name:              "Protocol v2 fetch",
			method:            http.MethodPost,
			path:              "/org/repo.git/git-upload-pack",
			body:              []byte("0011command=fetch\n0014agent=git/2.47.0\n0001000dthin-pack\n0032want 7f83b1657ff1fc5354dc1008ecf50686d3c52b78\n0009done\n0000"),
			expectedType:      RequestTypeUploadPackFetch,
			expectedCacheable: true,
		},
		{
			name:              "Protocol v0/v1 fetch",
			method:            http.MethodPost,
			path:              "/org/repo.git/git-upload-pack",
			body:              []byte("0032want 7f83b1657ff1fc5354dc1008ecf50686d3c52b78 multi_ack_detailed side-band-64k\n00000009done\n"),
			expectedType:      RequestTypeUploadPackFetch,
			expectedCacheable: true,
		},
		{
			name:              "Push ref discovery",
			method:            http.MethodGet,
			path:              "/org/repo.git/info/refs?service=git-receive-pack",
			expectedType:      RequestTypeReceivePack,
			expectedCacheable: false,
		},
		{
			name:              "Push upload-pack",
			method:            http.MethodPost,
			path:              "/org/repo.git/git-receive-pack",
			body:              []byte("003c0000000000000000000000000000000000000000 7f83b165 refs/heads/main\n"),
			expectedType:      RequestTypeReceivePack,
			expectedCacheable: false,
		},
		{
			name:              "Loose object SHA1",
			method:            http.MethodGet,
			path:              "/org/repo.git/objects/4b/825dc642cb6eb9a060e54bf8d69288fbee4904",
			expectedType:      RequestTypeObject,
			expectedCacheable: true,
		},
		{
			name:              "Packfile",
			method:            http.MethodGet,
			path:              "/org/repo.git/objects/pack/pack-1234567890abcdef1234567890abcdef12345678.pack",
			expectedType:      RequestTypeObject,
			expectedCacheable: true,
		},
		{
			name:              "Pack index",
			method:            http.MethodGet,
			path:              "/org/repo.git/objects/pack/pack-1234567890abcdef1234567890abcdef12345678.idx",
			expectedType:      RequestTypeObject,
			expectedCacheable: true,
		},
		{
			name:              "LFS object",
			method:            http.MethodGet,
			path:              "/org/repo.git/info/lfs/objects/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			expectedType:      RequestTypeObject,
			expectedCacheable: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			actualType := ClassifyGitRequest(req, tc.body)
			if actualType != tc.expectedType {
				t.Errorf("expected RequestType %v, got %v", tc.expectedType, actualType)
			}
			if actualType.IsCacheable() != tc.expectedCacheable {
				t.Errorf("expected IsCacheable %v, got %v", tc.expectedCacheable, actualType.IsCacheable())
			}
		})
	}
}

func makePktLine(s string) []byte {
	return []byte(fmt.Sprintf("%04x%s", len(s)+4, s))
}

func TestParseFetchRequest(t *testing.T) {
	var v2Valid bytes.Buffer
	v2Valid.Write(makePktLine("command=fetch\n"))
	v2Valid.Write(makePktLine("agent=git/2.47.0\n"))
	v2Valid.WriteString("0001") // Delim
	v2Valid.Write(makePktLine("thin-pack\n"))
	v2Valid.Write(makePktLine("ofs-delta\n"))
	v2Valid.Write(makePktLine("want 7f83b1657ff1fc5354dc1008ecf50686d3c52b78\n"))
	v2Valid.Write(makePktLine("have a94a8fe5ccb19ba61c4c0873d391e987982fbbd3\n"))
	v2Valid.Write(makePktLine("done\n"))
	v2Valid.WriteString("0000") // Flush

	var v0Valid bytes.Buffer
	v0Valid.Write(makePktLine("want 7f83b1657ff1fc5354dc1008ecf50686d3c52b78 multi_ack_detailed side-band-64k ofs-delta\n"))
	v0Valid.Write(makePktLine("have a94a8fe5ccb19ba61c4c0873d391e987982fbbd3\n"))
	v0Valid.WriteString("0000") // Flush
	v0Valid.Write(makePktLine("done\n"))

	var v2UnknownCmd bytes.Buffer
	v2UnknownCmd.Write(makePktLine("command=fetch\n"))
	v2UnknownCmd.Write(makePktLine("unknown-command\n"))
	v2UnknownCmd.Write(makePktLine("want 7f83b1657ff1fc5354dc1008ecf50686d3c52b78\n"))
	v2UnknownCmd.Write(makePktLine("done\n"))
	v2UnknownCmd.WriteString("0000")

	var v2Shallow bytes.Buffer
	v2Shallow.Write(makePktLine("command=fetch\n"))
	v2Shallow.Write(makePktLine("shallow 7f83b1657ff1fc5354dc1008ecf50686d3c52b78\n"))
	v2Shallow.Write(makePktLine("want 7f83b1657ff1fc5354dc1008ecf50686d3c52b78\n"))
	v2Shallow.Write(makePktLine("done\n"))
	v2Shallow.WriteString("0000")

	var v2Deepen bytes.Buffer
	v2Deepen.Write(makePktLine("command=fetch\n"))
	v2Deepen.Write(makePktLine("deepen 1\n"))
	v2Deepen.Write(makePktLine("want 7f83b1657ff1fc5354dc1008ecf50686d3c52b78\n"))
	v2Deepen.Write(makePktLine("done\n"))
	v2Deepen.WriteString("0000")

	var v2Filter bytes.Buffer
	v2Filter.Write(makePktLine("command=fetch\n"))
	v2Filter.Write(makePktLine("filter blob:none\n"))
	v2Filter.Write(makePktLine("want 7f83b1657ff1fc5354dc1008ecf50686d3c52b78\n"))
	v2Filter.Write(makePktLine("done\n"))
	v2Filter.WriteString("0000")

	var v0UnknownCap bytes.Buffer
	v0UnknownCap.Write(makePktLine("want 7f83b1657ff1fc5354dc1008ecf50686d3c52b78 unknown_capability\n"))
	v0UnknownCap.Write(makePktLine("done\n"))
	v0UnknownCap.WriteString("0000")

	var invalidOID bytes.Buffer
	invalidOID.Write(makePktLine("want not-a-valid-oid\n"))
	invalidOID.Write(makePktLine("done\n"))
	invalidOID.WriteString("0000")

	var noWants bytes.Buffer
	noWants.Write(makePktLine("command=fetch\n"))
	noWants.Write(makePktLine("done\n"))
	noWants.WriteString("0000")

	tests := []struct {
		name        string
		body        []byte
		expectErr   bool
		expectedReq *FetchRequest
	}{
		{
			name: "Valid v2 fetch request",
			body: v2Valid.Bytes(),
			expectedReq: &FetchRequest{
				Wants: []string{"7f83b1657ff1fc5354dc1008ecf50686d3c52b78"},
				Haves: []string{"a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"},
				IsV2:  true,
				Done:  true,
			},
		},
		{
			name: "Valid v0/v1 fetch request with capabilities",
			body: v0Valid.Bytes(),
			expectedReq: &FetchRequest{
				Wants: []string{"7f83b1657ff1fc5354dc1008ecf50686d3c52b78"},
				Haves: []string{"a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"},
				IsV2:  false,
				Done:  true,
			},
		},
		{
			name:      "Reject unknown command in v2",
			body:      v2UnknownCmd.Bytes(),
			expectErr: true,
		},
		{
			name:      "Reject shallow argument",
			body:      v2Shallow.Bytes(),
			expectErr: true,
		},
		{
			name:      "Reject deepen argument",
			body:      v2Deepen.Bytes(),
			expectErr: true,
		},
		{
			name:      "Reject filter argument",
			body:      v2Filter.Bytes(),
			expectErr: true,
		},
		{
			name:      "Reject unknown capability on want line",
			body:      v0UnknownCap.Bytes(),
			expectErr: true,
		},
		{
			name:      "Reject invalid OID format in want",
			body:      invalidOID.Bytes(),
			expectErr: true,
		},
		{
			name:      "Reject empty request",
			body:      []byte("0000"),
			expectErr: true,
		},
		{
			name:      "Reject request with no wants",
			body:      noWants.Bytes(),
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseFetchRequest(tc.body)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error for %s, but got none", tc.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", tc.name, err)
			}

			if parsed.IsV2 != tc.expectedReq.IsV2 {
				t.Errorf("expected IsV2=%v, got %v", tc.expectedReq.IsV2, parsed.IsV2)
			}
			if parsed.Done != tc.expectedReq.Done {
				t.Errorf("expected Done=%v, got %v", tc.expectedReq.Done, parsed.Done)
			}
			if len(parsed.Wants) != len(tc.expectedReq.Wants) {
				t.Errorf("expected %d wants, got %d", len(tc.expectedReq.Wants), len(parsed.Wants))
			} else {
				for i, w := range tc.expectedReq.Wants {
					if parsed.Wants[i] != w {
						t.Errorf("want[%d]: expected %s, got %s", i, w, parsed.Wants[i])
					}
				}
			}
			if len(parsed.Haves) != len(tc.expectedReq.Haves) {
				t.Errorf("expected %d haves, got %d", len(tc.expectedReq.Haves), len(parsed.Haves))
			} else {
				for i, h := range tc.expectedReq.Haves {
					if parsed.Haves[i] != h {
						t.Errorf("have[%d]: expected %s, got %s", i, h, parsed.Haves[i])
					}
				}
			}
		})
	}
}
