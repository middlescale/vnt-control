# vnt-control

`vnt-control` 是 `vnts` 的 Go 重写控制面项目，目标是将控制面与网关转发面解耦：客户端通过 QUIC 与控制服务通信完成认证与状态同步，数据转发由独立 gateway 集群负责。

## 目标架构分层

- `vnts` / `vnt-control`（Control Plane）：
  - 用户/设备认证
  - 注册与会话管理
  - 在线状态、设备列表、NAT 信息等状态更新
- `gateway` 集群（Data Plane）：
  - 数据包转发与中继
  - 横向扩展与高可用
- `vnt` 客户端：
  - 通过 QUIC 与控制面交互
  - 按控制面下发信息选择/切换数据路径

## 目录结构

- `main.go`：服务启动入口，加载配置、初始化 TLS、启动 QUIC 服务。
- `config/`：配置定义与默认配置文件。
- `handlers/`：QUIC / WebSocket / 状态接口处理。
- `control/`：握手、注册、虚拟 IP 分配等核心控制逻辑。
- `protocol/`、`proto/`：协议定义与 protobuf 生成代码。

## 配置

默认读取 `config/config.json`（不存在时回退 `config.json`）。

示例：

```json
{
  "gateway": "10.26.0.1",
  "domain": "ms.net",
  "netmask": "255.255.255.0",
  "listen_addr": ":4433",
  "cert_cache_dir": "./cert-cache"
}
```

可选字段：

- `autocert_domain`：启用 `autocert` 时用于签发证书的域名。
- `tls_cert_path` / `tls_key_path`：使用本地证书文件。
- `client_ca_path`：客户端 CA 文件路径（PEM）。
- `require_client_cert`：是否强制客户端证书校验（mTLS）。

## 环境变量（优先级高于配置文件）

- `CONFIG_PATH`
- `LISTEN_ADDR`
- `TLS_CERT` / `TLS_KEY`
- `AUTOCERT_DOMAIN`
- `CERT_CACHE_DIR`
- `TLS_CLIENT_CA`
- `TLS_REQUIRE_CLIENT_CERT`
- `LOG_LEVEL`

## 使用 Makefile 编译与运行

```bash
cd vnt-control
make build
```

编译产物为当前目录下的 `./vnt-control`。

常用命令：

```bash
make run     # 运行已编译二进制
make clean   # 删除二进制
make proto   # 重新生成 proto Go 代码（需安装 protoc 与插件）
```

## 验证

```bash
go test ./...
```

## 迁移方向（简要）

1. 继续补齐与 `vnts` 对齐的控制面协议行为（认证、注册、状态同步）。
2. 以 QUIC + 证书校验作为控制面主链路。
3. 将数据转发能力下沉到可集群化的 gateway 服务，实现控制面与转发面独立扩缩容。
