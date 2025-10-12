FROM golang:1.25.2-alpine3.22 AS builder

WORKDIR /temp

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY main.go main.go
COPY ziputil ziputil
RUN apk update && apk add --no-cache gcc g++ musl musl-dev libc-dev libc++-dev build-base && rm -rf /var/cache/apk/*
RUN CGO_ENABLED=1 go build -o app .

FROM alpine:3.22
COPY --from=builder /temp/app /app

RUN apk update && apk add --no-cache gcc g++ musl && rm -rf /var/cache/apk/*

WORKDIR /work

ENTRYPOINT ["/app"]
