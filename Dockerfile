# Pin base images to SHA256 digests for supply-chain security.
# Update digests via: docker manifest inspect golang:1.25 | jq '.digest'
# TODO: Replace these with current digests from CI before first release.
ARG GOLANG_IMAGE=golang:1.25
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

# TODO: Replace with current digest from CI before first release.
ARG RUNTIME_IMAGE=gcr.io/distroless/static:nonroot
FROM ${RUNTIME_IMAGE}
# In CI/release, always override with pinned digest:
#   --build-arg RUNTIME_IMAGE=gcr.io/distroless/static:nonroot@sha256:<digest>

WORKDIR /
COPY --from=builder /workspace/varax .

USER 65532:65532

ENTRYPOINT ["/varax"]
