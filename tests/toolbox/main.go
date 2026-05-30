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

		body, _ := io.ReadAll(r.Body)

		resp := map[string]interface{}{
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
	defer resp.Body.Close()

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

		resp := map[string]interface{}{
			"login": "mock-github-user",
			"id":    12345678,
			"name":  "Mock GitHub User",
			"bio":   "This is a mock GitHub server.",
			"request_metadata": map[string]interface{}{
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

		resp := map[string]interface{}{
			"id":        987654321,
			"name":      repo,
			"full_name": owner + "/" + repo,
			"private":   false,
			"html_url":  "https://github.com/" + owner + "/" + repo,
			"request_metadata": map[string]interface{}{
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

		fmt.Fprintf(w, "Keep it simple, stupid.\n\nRequest Headers:\n")
		for k, v := range headers {
			fmt.Fprintf(w, "%s: %v\n", k, v)
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[mock-github] Received request (fallback): %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}

		resp := map[string]interface{}{
			"message": "Welcome to the Mock GitHub Server (Fallback endpoint)",
			"request_metadata": map[string]interface{}{
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

		resp := map[string]interface{}{
			"models": []map[string]interface{}{
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
			"request_metadata": map[string]interface{}{
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

		resp := map[string]interface{}{
			"candidates": []map[string]interface{}{
				{
					"content": map[string]interface{}{
						"parts": []map[string]interface{}{
							{
								"text": "Hello! This is a mock response from the Gemini API.",
							},
						},
						"role": "model",
					},
					"finishReason": "STOP",
				},
			},
			"request_metadata": map[string]interface{}{
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

		resp := map[string]interface{}{
			"models": []map[string]interface{}{
				{
					"name":        "models/gemini-1.5-pro",
					"version":     "1.5-pro",
					"displayName": "Gemini 1.5 Pro",
				},
			},
			"request_metadata": map[string]interface{}{
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

		resp := map[string]interface{}{
			"candidates": []map[string]interface{}{
				{
					"content": map[string]interface{}{
						"parts": []map[string]interface{}{
							{
								"text": "Hello! This is a mock response from the Gemini API v1.",
							},
						},
						"role": "model",
					},
					"finishReason": "STOP",
				},
			},
			"request_metadata": map[string]interface{}{
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

		resp := map[string]interface{}{
			"message": "Welcome to the Mock Gemini Server (Fallback endpoint)",
			"request_metadata": map[string]interface{}{
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
