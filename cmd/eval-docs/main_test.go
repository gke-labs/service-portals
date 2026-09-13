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
	"context"
	"os"
	"path/filepath"
	"testing"
)

// mockGeminiClient is a test mock implementation of GeminiClient.
type mockGeminiClient struct {
	response string
	err      error
}

func (m *mockGeminiClient) GenerateContent(ctx context.Context, prompt string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.response, nil
}

func TestRunEvaluation(t *testing.T) {
	// Create a temporary workspace directory for testing.
	tempDir, err := os.MkdirTemp("", "eval-docs-test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a mock doc file.
	docName := "MOCK_README.md"
	docPath := filepath.Join(tempDir, docName)
	docContent := "To install from source, use: IMAGE_PREFIX=example.com/foo ap deploy //..."
	if err := os.WriteFile(docPath, []byte(docContent), 0644); err != nil {
		t.Fatalf("Failed to write mock doc file: %v", err)
	}

	// Create a mock scenario YAML file.
	evalsDir := filepath.Join(tempDir, "evals", "docs")
	if err := os.MkdirAll(evalsDir, 0755); err != nil {
		t.Fatalf("Failed to create evals dir: %v", err)
	}

	scenarioYAML := `
scenario: install_from_source
description: "User wants to know how to install from source using ap."
questions:
  - "How do I install from source?"
documents_to_cite:
  - "MOCK_README.md"
expected_key_elements:
  - "IMAGE_PREFIX="
  - "ap deploy //..."
`
	scenarioPath := filepath.Join(evalsDir, "scenario.yaml")
	if err := os.WriteFile(scenarioPath, []byte(scenarioYAML), 0644); err != nil {
		t.Fatalf("Failed to write mock scenario file: %v", err)
	}

	t.Run("passing evaluation", func(t *testing.T) {
		mockClient := &mockGeminiClient{
			response: "You can install from source with IMAGE_PREFIX=example.com/foo ap deploy //...",
		}

		success, err := runEvaluation(context.Background(), mockClient, tempDir, evalsDir)
		if err != nil {
			t.Fatalf("runEvaluation failed: %v", err)
		}

		if !success {
			t.Errorf("expected evaluation to succeed, but it failed")
		}
	})

	t.Run("failing evaluation - missing elements", func(t *testing.T) {
		mockClient := &mockGeminiClient{
			response: "Just run install without any other flags.",
		}

		success, err := runEvaluation(context.Background(), mockClient, tempDir, evalsDir)
		if err != nil {
			t.Fatalf("runEvaluation failed: %v", err)
		}

		if success {
			t.Errorf("expected evaluation to fail, but it succeeded")
		}
	})
}
