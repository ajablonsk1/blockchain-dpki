FROM golang:1.25.1-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /pki-node .

FROM alpine:latest
COPY --from=builder /pki-node /usr/bin/pki-node
ENTRYPOINT ["pki-node"]
