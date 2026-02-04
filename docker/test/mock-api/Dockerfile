# Mock API 服务容器
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY main.go .

RUN go build -o mock-api main.go

# 运行镜像
FROM alpine:3.19

RUN apk add --no-cache ca-certificates openssl bash

WORKDIR /app

COPY --from=builder /app/mock-api /usr/local/bin/mock-api

# 生成默认测试证书
RUN mkdir -p /certs && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /certs/default.key \
        -out /certs/default.crt \
        -subj "/CN=test.example.com/O=MockAPI/C=CN"

EXPOSE 8080

CMD ["mock-api", "-port", "8080", "-cert", "/certs/default.crt", "-key", "/certs/default.key", "-cn", "test.example.com"]
