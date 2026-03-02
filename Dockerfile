# Pin base images via ARG for reproducible builds.
# Override with --build-arg GOLANG_IMAGE=golang:1.25@sha256:<digest>
ARG GOLANG_IMAGE=golang:1.25
FROM ${GOLANG_IMAGE} AS builder

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o varax ./cmd/varax/

ARG RUNTIME_IMAGE=gcr.io/distroless/static:nonroot
FROM ${RUNTIME_IMAGE}

WORKDIR /
COPY --from=builder /workspace/varax .

USER 65532:65532

ENTRYPOINT ["/varax"]
