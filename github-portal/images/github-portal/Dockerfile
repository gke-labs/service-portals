# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Use the official Golang image to create a build artifact.
FROM golang:1.26.4 AS builder

WORKDIR /app

# Copy the Go module files
COPY go.mod go.sum ./

# Download the Go module dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /github-portal ./github-portal/cmd/github-portal/main.go

# Use a minimal base image to package the application
FROM gcr.io/distroless/static:nonroot

WORKDIR /

COPY --from=builder /github-portal /github-portal

# Run as non-root user
USER 65532:65532

ENTRYPOINT ["/github-portal"]
