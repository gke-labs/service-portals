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

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestOpenTelemetryProxy(t *testing.T) {
	// Set the env var to enable OpenTelemetry
	os.Setenv("OTEL_INSTRUMENTATION_ENABLED", "true")
	defer os.Unsetenv("OTEL_INSTRUMENTATION_ENABLED")

	// Set standard propagator for tracing propagation
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	// Set up a real SDK TracerProvider so we get valid trace IDs
	tp := sdktrace.NewTracerProvider()
	otel.SetTracerProvider(tp)
	defer func() {
		_ = tp.Shutdown(context.Background())
	}()

	var capturedHeaders http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	p, err := NewHTTPProxy(u, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Create context with a valid span
	tracer := otel.GetTracerProvider().Tracer("test-tracer")
	ctx, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	req, err := http.NewRequestWithContext(ctx, "GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.Transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}

	// Verify traceparent is present in the outgoing request headers
	if capturedHeaders == nil {
		t.Fatal("no request captured by the backend server")
	}

	traceparent := capturedHeaders.Get("Traceparent")
	if traceparent == "" {
		t.Error("expected traceparent header to be present on the outgoing request, but got none")
	}
}
