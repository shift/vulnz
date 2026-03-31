FROM golang:1.25-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w -X github.com/shift/vulnz/internal/cli.Version=dev" \
    -o /vulnz ./cmd/vulnz

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=builder /vulnz /usr/local/bin/vulnz

WORKDIR /data

ENTRYPOINT ["vulnz"]
CMD ["run", "--all"]
