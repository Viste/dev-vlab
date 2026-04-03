FROM node:22-alpine AS frontend

WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ .
RUN npm run build

FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git gcc musl-dev

WORKDIR /build
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o api ./cmd/api

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata
RUN adduser -D -g '' appuser
USER appuser

WORKDIR /app
COPY --from=builder /build/api .
COPY --from=frontend /build/dist ./static

ENV STATIC_DIR=/app/static
EXPOSE 8000

CMD ["./api"]
