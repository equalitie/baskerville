FROM golang:1.24 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . ./

#build static-ish binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o server ./main.go

#runtime img
FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/server /server

#non root user (using useradd instead of adduser)
RUN useradd -m -s /usr/sbin/nologin server-user
USER server-user


HEALTHCHECK --interval=30s --timeout=30s --retries=3 \
  CMD curl -f http://localhost:8089/health || exit 1

CMD ["/server"]
