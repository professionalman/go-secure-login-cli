FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/auth-cli ./cmd/cli

FROM alpine:3.23

RUN apk add --no-cache ca-certificates \
    && addgroup -S app \
    && adduser -S -G app app \
    && mkdir -p /app/data /app/migrations \
    && chown -R app:app /app

WORKDIR /app

COPY --from=build /out/auth-cli /app/auth-cli
COPY --chown=app:app migrations/ /app/migrations/

USER app

ENTRYPOINT ["/app/auth-cli"]
