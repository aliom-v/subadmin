FROM golang:1.22-alpine AS builder

ENV GOSUMDB=off

WORKDIR /src/backend
COPY . .
RUN go mod tidy
RUN go build -trimpath -ldflags='-s -w' -o /out/subadmin-api ./cmd/server

FROM alpine:3.20

ENV DATA_DIR=/data \
    DB_PATH=/data/subadmin.db \
    CACHE_DIR=/data/cache

RUN mkdir -p /data/cache

COPY --from=builder /out/subadmin-api /usr/local/bin/subadmin-api
EXPOSE 8080

CMD ["subadmin-api"]
