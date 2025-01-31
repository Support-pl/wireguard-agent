FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . ./

RUN go build -o nocloud-watcher ./


FROM ghcr.io/support-pl/wg-easy:latest

WORKDIR /app

COPY --from=builder /app/nocloud-watcher ./

HEALTHCHECK none

ENTRYPOINT ["./nocloud-watcher"]