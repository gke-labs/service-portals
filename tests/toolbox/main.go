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
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: toolbox <server|client|mock-github|mock-gemini> [args]")
	}

	mode := os.Args[1]
	switch mode {
	case "server":
		runServer()
	case "client":
		if len(os.Args) < 3 {
			log.Fatal("Usage: toolbox client <url>")
		}
		runClient(os.Args[2])
	case "mock-github":
		runMockGithub()
	case "mock-gemini":
		runMockGemini()
	default:
		log.Fatalf("Unknown mode: %s", mode)
	}
}

func runServer() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Failed to read body: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := map[string]any{
			"headers": headers,
			"body":    string(body),
			"method":  r.Method,
			"path":    r.URL.Path,
		}

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("Failed to encode response: %v", err)
		}
	})

	log.Printf("Starting echo server on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func runClient(targetURL string) {
	log.Printf("Sending request to %s", targetURL)
	resp, err := http.Get(targetURL)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Failed to close response body: %v", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Body: %s\n", string(body))
}

func runMockGithub() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[mock-github] Received request: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}

		resp := map[string]any{
			"login": "mock-github-user",
			"id":    12345678,
			"name":  "Mock GitHub User",
			"bio":   "This is a mock GitHub server.",
			"request_metadata": map[string]any{
				"headers": headers,
				"method":  r.Method,
				"path":    r.URL.Path,
			},
			"headers": headers,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("[mock-github] Failed to encode response: %v", err)
		}
	})

	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[mock-github] Received request: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}

		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/repos/"), "/")
		owner := "mock-owner"
		repo := "mock-repo"
		if len(parts) >= 2 {
			owner = parts[0]
			repo = parts[1]
		}

		resp := map[string]any{
			"id":        987654321,
			"name":      repo,
			"full_name": owner + "/" + repo,
			"private":   false,
			"html_url":  "https://github.com/" + owner + "/" + repo,
			"request_metadata": map[string]any{
				"headers": headers,
				"method":  r.Method,
				"path":    r.URL.Path,
			},
			"headers": headers,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("[mock-github] Failed to encode response: %v", err)
		}
	})

	mux.HandleFunc("/zen", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[mock-github] Received request: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "text/plain")

		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}

		if _, err := fmt.Fprintf(w, "Keep it simple, stupid.\n\nRequest Headers:\n"); err != nil {
			log.Printf("[mock-github] Failed to write response: %v", err)
			return
		}
		for k, v := range headers {
			if _, err := fmt.Fprintf(w, "%s: %v\n", k, v); err != nil {
				log.Printf("[mock-github] Failed to write header: %v", err)
				return
			}
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[mock-github] Received request (fallback): %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}

		resp := map[string]any{
			"message": "Welcome to the Mock GitHub Server (Fallback endpoint)",
			"request_metadata": map[string]any{
				"headers": headers,
				"method":  r.Method,
				"path":    r.URL.Path,
			},
			"headers": headers,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("[mock-github] Failed to encode response: %v", err)
		}
	})

	log.Printf("Starting mock github server on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func runMockGemini() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/v1beta/models", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[mock-gemini] Received request: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}

		resp := map[string]any{
			"models": []map[string]any{
				{
					"name":        "models/gemini-1.5-pro",
					"version":     "1.5-pro",
					"displayName": "Gemini 1.5 Pro",
					"description": "Mock Gemini 1.5 Pro",
				},
				{
					"name":        "models/gemini-1.5-flash",
					"version":     "1.5-flash",
					"displayName": "Gemini 1.5 Flash",
					"description": "Mock Gemini 1.5 Flash",
				},
			},
			"request_metadata": map[string]any{
				"headers": headers,
				"method":  r.Method,
				"path":    r.URL.Path,
			},
			"headers": headers,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("[mock-gemini] Failed to encode response: %v", err)
		}
	})

	mux.HandleFunc("/v1beta/models/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[mock-gemini] Received request: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}

		resp := map[string]any{
			"candidates": []map[string]any{
				{
					"content": map[string]any{
						"parts": []map[string]any{
							{
								"text": "Hello! This is a mock response from the Gemini API.",
							},
						},
						"role": "model",
					},
					"finishReason": "STOP",
				},
			},
			"request_metadata": map[string]any{
				"headers": headers,
				"method":  r.Method,
				"path":    r.URL.Path,
			},
			"headers": headers,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("[mock-gemini] Failed to encode response: %v", err)
		}
	})

	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[mock-gemini] Received request: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}

		resp := map[string]any{
			"models": []map[string]any{
				{
					"name":        "models/gemini-1.5-pro",
					"version":     "1.5-pro",
					"displayName": "Gemini 1.5 Pro",
				},
			},
			"request_metadata": map[string]any{
				"headers": headers,
				"method":  r.Method,
				"path":    r.URL.Path,
			},
			"headers": headers,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("[mock-gemini] Failed to encode response: %v", err)
		}
	})

	mux.HandleFunc("/v1/models/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[mock-gemini] Received request: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}

		resp := map[string]any{
			"candidates": []map[string]any{
				{
					"content": map[string]any{
						"parts": []map[string]any{
							{
								"text": "Hello! This is a mock response from the Gemini API v1.",
							},
						},
						"role": "model",
					},
					"finishReason": "STOP",
				},
			},
			"request_metadata": map[string]any{
				"headers": headers,
				"method":  r.Method,
				"path":    r.URL.Path,
			},
			"headers": headers,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("[mock-gemini] Failed to encode response: %v", err)
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[mock-gemini] Received request (fallback): %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}

		resp := map[string]any{
			"message": "Welcome to the Mock Gemini Server (Fallback endpoint)",
			"request_metadata": map[string]any{
				"headers": headers,
				"method":  r.Method,
				"path":    r.URL.Path,
			},
			"headers": headers,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("[mock-gemini] Failed to encode response: %v", err)
		}
	})

	log.Printf("Starting mock gemini server on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
