FROM golang:1.25-alpine AS builder

RUN apk add --no-cache gcc musl-dev sqlite-dev git

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" GOOS=linux go build -o veritysec ./cmd/server

# --- Runtime ---
FROM alpine:3.20

RUN apk add --no-cache ca-certificates sqlite-libs tzdata

WORKDIR /app
COPY --from=builder /app/veritysec .
COPY --from=builder /app/config.example.yaml ./config.yaml
COPY --from=builder /app/web ./web
COPY --from=builder /app/tools ./tools
COPY --from=builder /app/roles ./roles
COPY --from=builder /app/skills ./skills
COPY --from=builder /app/agents ./agents

RUN addgroup -S app && adduser -S -G app -h /app -s /sbin/nologin app \
 && mkdir -p /app/data /app/data/evidence /app/log /app/chat_uploads /app/tmp/reduction /app/tmp/workspace /app/tmp/c2 \
 && chown -R app:app /app/data /app/log /app/chat_uploads /app/tmp

ENV GIN_MODE=release \
    TLS_ENABLED=false \
    HOST=0.0.0.0 \
    PORT=8765

USER app
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8765/api/health || exit 1

CMD ["./veritysec", "--http"]
