APP_NAME=vnt-control
GO_FILES=$(shell find . -name '*.go' -not -path "./vendor/*")
PROTO_DIR=proto
PROTO_FILES=$(wildcard $(PROTO_DIR)/*.proto)
GEN_GO_DIR=protocol/pb

.PHONY: all build run clean cert proto

all: build

build:
	go build -o $(APP_NAME) main.go

run:
	./$(APP_NAME)

clean:
	rm -f $(APP_NAME)

cert:
	@echo "证书由 autocert 自动管理，无需手动生成。"

# 编译 proto 文件为 Go 代码
proto:
	mkdir -p $(GEN_GO_DIR)
	cd $(PROTO_DIR) && protoc --go_out=../$(GEN_GO_DIR) --go_opt=paths=source_relative --go-grpc_out=../$(GEN_GO_DIR) --go-grpc_opt=paths=source_relative *.proto
