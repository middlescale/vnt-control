APP_NAME=vnt-control
GO_FILES=$(shell find . -name '*.go' -not -path "./vendor/*")

.PHONY: all build run clean cert

all: build

build:
	go build -o $(APP_NAME) main.go

run:
	./$(APP_NAME)

clean:
	rm -f $(APP_NAME)

cert:
	@echo "证书由 autocert 自动管理，无需手动生成。"
