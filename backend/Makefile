.PHONY: build run dev tidy lint clean

APP_NAME=vlab-api
BUILD_DIR=./bin

build:
	go build -ldflags="-w -s" -o $(BUILD_DIR)/$(APP_NAME) ./cmd/api

run: build
	$(BUILD_DIR)/$(APP_NAME)

dev:
	go run ./cmd/api

tidy:
	go mod tidy

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BUILD_DIR)
