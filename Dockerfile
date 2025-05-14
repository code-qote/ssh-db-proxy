FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata build-base

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o db-proxy ./cmd/db-proxy

FROM alpine:3.16

RUN apk add --no-cache ca-certificates tzdata

RUN adduser -D -H -h /app appuser

RUN mkdir -p /app /etc/app /opt/run/tls/notifier && \
    chown -R appuser:appuser /app /etc/app

COPY --from=builder /app/db-proxy /app/db-proxy
RUN chmod +x /app/db-proxy

USER appuser
WORKDIR /app

ENTRYPOINT ["/app/db-proxy"]
