FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY main.go .
RUN go build -o toolbox main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/toolbox .
ENTRYPOINT ["./toolbox"]
