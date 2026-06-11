# Build stage. Protobuf stubs (*.pb.go) are committed, so no protoc is needed.
FROM golang:1.25-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /out/dpkid ./cmd/dpkid && \
    go build -o /out/dpki-cli ./cmd/dpki-cli

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/dpkid /out/dpki-cli /usr/local/bin/

# The node home defaults to $HOME/.dpkid (or $CMTHOME); compose mounts the
# per-validator directory there.
ENTRYPOINT ["dpkid"]
CMD ["start"]
