# export env variables
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

.PHONY: install run build upgrade clean

# vars
APP_NAME=softutils_golang

default: run

install:
	@echo "Installing dependencies"
	@go install github.com/cosmtrek/air@latest
	@go mod tidy

run:
	@echo "Running the application"
	@go mod tidy 
	@go run ./examples/auth_example.go

build:
	@echo "Building the application"

upgrade: 
	@echo "Upgrading go mod packages..."
	@go get -u ./...

clean:
	@echo "Cleaning the application"
	@rm -rf bin
