# Pin base images to SHA256 digests for supply-chain security.
# Update digests via: docker manifest inspect golang:1.25 | jq '.digest'
ARG GOLANG_IMAGE=golang:1.25@sha256:779b230b2508037a8095c9e2d223a6405f8426e12233b694dbae50197b9f6d04
FROM ${GOLANG_IMAGE} AS builder
# In CI/release, always override with pinned digest:
#   --build-arg GOLANG_IMAGE=golang:1.25@sha256:<digest>

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o varax ./cmd/varax/

ARG RUNTIME_IMAGE=gcr.io/distroless/static:nonroot@sha256:f512d819b8f109f2375e8b51d8cfd8aafe81034bc3e319740128b7d7f70d5036
FROM ${RUNTIME_IMAGE}
# In CI/release, always override with pinned digest:
#   --build-arg RUNTIME_IMAGE=gcr.io/distroless/static:nonroot@sha256:<digest>

WORKDIR /
COPY --from=builder /workspace/varax .

USER 65532:65532

ENTRYPOINT ["/varax"]
