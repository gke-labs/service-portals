# Use the official Golang image to create a build artifact.
FROM golang:1.23 as builder

WORKDIR /app

# Copy the Go module files
COPY go.mod ./

# Download the Go module dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o service-portal ./cmd/service-portal/main.go

# Use a minimal base image to package the application
FROM gcr.io/distroless/static:nonroot

WORKDIR /

COPY --from=builder /app/service-portal /service-portal

# Run as non-root user
USER 65532:65532

ENTRYPOINT ["/service-portal"]
