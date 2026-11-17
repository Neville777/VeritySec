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
COPY --from=builder /app/config.yaml .
COPY --from=builder /app/web ./web
COPY --from=builder /app/tools ./tools
COPY --from=builder /app/roles ./roles
COPY --from=builder /app/skills ./skills
COPY --from=builder /app/agents ./agents

RUN mkdir -p /app/data /app/data/evidence /app/log /app/chat_uploads /app/tmp/reduction /app/tmp/workspace /app/tmp/c2

ENV GIN_MODE=release
ENV TLS_ENABLED=false

EXPOSE 8765

CMD ["./veritysec"]
