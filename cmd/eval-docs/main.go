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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Scenario represents an evaluation scenario parsed from YAML.
type Scenario struct {
	Scenario            string   `yaml:"scenario"`
	Description         string   `yaml:"description"`
	Questions           []string `yaml:"questions"`
	DocumentsToCite     []string `yaml:"documents_to_cite"`
	ExpectedKeyElements []string `yaml:"expected_key_elements"`
}

// GeminiClient defines the interface for interacting with the Gemini API.
type GeminiClient interface {
	GenerateContent(ctx context.Context, prompt string) (string, error)
}

// realGeminiClient implements GeminiClient using direct HTTP REST requests.
type realGeminiClient struct {
	apiKey string
	model  string
}

func (c *realGeminiClient) GenerateContent(ctx context.Context, prompt string) (string, error) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", c.model, c.apiKey)

	type Part struct {
		Text string `json:"text"`
	}
	type Content struct {
		Parts []Part `json:"parts"`
	}
	type RequestBody struct {
		Contents []Content `json:"contents"`
	}

	reqBody := RequestBody{
		Contents: []Content{
			{
				Parts: []Part{
					{Text: prompt},
				},
			},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	type Candidate struct {
		Content struct {
			Parts []Part `json:"parts"`
		} `json:"content"`
	}
	type ResponseBody struct {
		Candidates []Candidate `json:"candidates"`
	}

	var respBody ResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return "", fmt.Errorf("failed to decode response body: %w", err)
	}

	if len(respBody.Candidates) == 0 || len(respBody.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("empty response from Gemini API")
	}

	return respBody.Candidates[0].Content.Parts[0].Text, nil
}

// runEvaluation processes the scenarios and evaluates the documentation.
func runEvaluation(ctx context.Context, client GeminiClient, workspaceDir string, evalDocsDir string) (bool, error) {
	pattern := filepath.Join(evalDocsDir, "*.yaml")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return false, fmt.Errorf("failed to glob yaml files: %w", err)
	}

	if len(files) == 0 {
		fmt.Printf("No evaluation files found matching pattern: %s\n", pattern)
		return true, nil
	}

	allPassed := true

	for _, file := range files {
		fmt.Printf("\n--- Processing evaluation: %s ---\n", filepath.Base(file))
		yamlBytes, err := os.ReadFile(file)
		if err != nil {
			return false, fmt.Errorf("failed to read scenario file %s: %w", file, err)
		}

		var scenario Scenario
		if err := yaml.Unmarshal(yamlBytes, &scenario); err != nil {
			return false, fmt.Errorf("failed to unmarshal scenario from %s: %w", file, err)
		}

		fmt.Printf("Scenario: %s\nDescription: %s\n", scenario.Scenario, scenario.Description)

		// 1. Gather all referenced documents
		var docContextBuilder strings.Builder
		for _, docPath := range scenario.DocumentsToCite {
			fullPath := filepath.Join(workspaceDir, docPath)
			docBytes, err := os.ReadFile(fullPath)
			if err != nil {
				fmt.Printf("Warning: failed to read document %s referenced in scenario: %v\n", docPath, err)
				continue
			}
			docContextBuilder.WriteString(fmt.Sprintf("\n--- FILE: %s ---\n", docPath))
			docContextBuilder.Write(docBytes)
			docContextBuilder.WriteString("\n-------------------\n")
		}

		docContext := docContextBuilder.String()
		if len(docContext) == 0 {
			fmt.Printf("Warning: empty documentation context, proceeding anyway\n")
		}

		// 2. Evaluate each question
		for _, question := range scenario.Questions {
			fmt.Printf("\nEvaluating Question: %q\n", question)

			prompt := fmt.Sprintf(`You are an assistant designed to answer questions about the service-portals package based solely on the provided documentation context.

--- DOCUMENTATION CONTEXT ---
%s
-----------------------------

Question: %s

Provide a concise answer based ONLY on the documentation context above. Do not assume or extrapolate anything not explicitly mentioned.`, docContext, question)

			answer, err := client.GenerateContent(ctx, prompt)
			if err != nil {
				fmt.Printf("Error generating content from LLM: %v\n", err)
				allPassed = false
				continue
			}

			fmt.Printf("LLM Response:\n%s\n", strings.TrimSpace(answer))

			// Check expected key elements
			missingElements := []string{}
			for _, element := range scenario.ExpectedKeyElements {
				if !strings.Contains(answer, element) {
					missingElements = append(missingElements, element)
				}
			}

			if len(missingElements) == 0 {
				fmt.Printf("Result: [PASS] All %d expected key elements found.\n", len(scenario.ExpectedKeyElements))
			} else {
				fmt.Printf("Result: [FAIL] Missing expected key elements: %q\n", missingElements)
				allPassed = false
			}
		}
	}

	return allPassed, nil
}

func main() {
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "Error: GEMINI_API_KEY environment variable is not set")
		os.Exit(1)
	}

	workspaceDir := os.Getenv("WORKSPACE_DIR")
	if workspaceDir == "" {
		// Default to current directory
		var err error
		workspaceDir, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting current working directory: %v\n", err)
			os.Exit(1)
		}
	}

	evalDocsDir := filepath.Join(workspaceDir, "evals", "docs")

	client := &realGeminiClient{
		apiKey: apiKey,
		model:  "gemini-2.5-flash",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	success, err := runEvaluation(ctx, client, workspaceDir, evalDocsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Evaluation runner failed with error: %v\n", err)
		os.Exit(1)
	}

	if !success {
		fmt.Println("\nEvaluation failed.")
		os.Exit(1)
	}

	fmt.Println("\nAll evaluations passed successfully!")
}
