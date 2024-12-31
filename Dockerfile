FROM golang:1.21-alpine

WORKDIR /app

# 添加这些依赖
RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# 先构建可执行文件
RUN go build -o main .

EXPOSE 8080

# 运行构建后的文件
CMD ["./main"]