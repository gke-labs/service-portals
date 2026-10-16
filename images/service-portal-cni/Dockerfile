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

FROM golang:1.27.2-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/service-portal-cni ./cmd/service-portal-cni
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/service-portal-cni ./cmd/service-portal-cni

FROM alpine:3.20

RUN apk add --no-cache jq

COPY --from=builder /bin/service-portal-cni /usr/local/bin/service-portal-cni
COPY images/service-portal-cni/install-cni.sh /usr/local/bin/install-cni.sh
RUN chmod +x /usr/local/bin/install-cni.sh /usr/local/bin/service-portal-cni

ENTRYPOINT ["/usr/local/bin/install-cni.sh"]
