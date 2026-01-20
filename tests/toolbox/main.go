package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: toolbox <server|client> [args]")
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
