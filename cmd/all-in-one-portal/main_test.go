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

package main

import (
	"flag"
	"os"
	"testing"
)

func TestFlags(t *testing.T) {
	// Backup original args and reset flags
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	os.Args = []string{"cmd", "-rules-dir", "/tmp/rules"}

	// Reset CommandLine so we can redefine/reparse flags
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	rulesDir := flag.String("rules-dir", "", "Directory containing configuration rules")
	flag.Parse()

	if *rulesDir != "/tmp/rules" {
		t.Errorf("expected rules-dir to be /tmp/rules, got %q", *rulesDir)
	}
}
