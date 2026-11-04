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

FROM kindest/node:v1.37.0

# Pin gVisor release (https://github.com/google/gvisor/releases).
# To bump: update GVISOR_VERSION to the target dated release (e.g. 20261102.0).
# The build verifies the published .sha512 checksum next to the downloaded tarball.
ARG GVISOR_VERSION=20261102.0

# Install gVisor (runsc, containerd-shim-runsc-v1, and sidecars in gvisor-bin)
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates bzip2 \
    && ARCH="$(uname -m)" \
    && cd /tmp \
    && curl -fsSLO "https://storage.googleapis.com/gvisor/releases/release/${GVISOR_VERSION}/${ARCH}/gvisor.tar.bz2" \
    && curl -fsSLO "https://storage.googleapis.com/gvisor/releases/release/${GVISOR_VERSION}/${ARCH}/gvisor.tar.bz2.sha512" \
    && sha512sum -c gvisor.tar.bz2.sha512 \
    && tar -xj -C /usr/local/bin -f gvisor.tar.bz2 \
    && rm -f gvisor.tar.bz2 gvisor.tar.bz2.sha512 \
    && apt-get purge -y bzip2 && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
