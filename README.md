# sdl-control

`sdl-control` 是 `vnts` 的 Go 重写控制面项目，目标是将控制面与网关转发面解耦：客户端和 gateway 通过 HTTP/3 `/control` 与控制服务通信完成认证与状态同步，数据转发由独立 gateway 集群负责。

从产品语义上看，这个项目更贴近 **SDL (Software Defined LAN)**：通过控制平面把分散在 WAN / Internet 上的节点组织成一个 overlay LAN，而不是传统 SD-WAN 的选路优化产品。

## 目标架构分层

- `vnts` / `sdl-control`（Control Plane）：
  - 用户/设备认证
  - 注册与会话管理
  - 控制面在线状态、设备列表、NAT 信息等状态更新
- `gateway` 集群（Data Plane）：
  - 数据包转发与中继
  - 横向扩展与高可用
- `sdl` 客户端：
  - 通过 HTTP/3 `/control` 与控制面交互
  - 按控制面下发信息选择/切换数据路径

> 过渡说明：仓库、二进制与主要运行时命名已经切到 `sdl*`；仍有少量内部实现/历史术语保留旧命名，后续会继续收口。

## 在线状态语义（当前实现）

- `ControlOnline`：表示客户端是否与控制面保持活跃（注册、控制 ping、状态上报都会刷新）。
- `DataPlaneReachable`：表示数据面可达性（当前按 `ClientStatusInfo.p2p_list` 是否非空判定）。
- `DeviceStatus` 当前按 `ControlOnline` 对外映射：在线为 `0`，离线为 `1`。

> 说明：当前 `DataPlaneReachable` 语义是“P2P 可达”，尚未包含仅 relay/gateway 可达场景，后续会扩展。

## 目录结构

- `main.go`：服务启动入口，加载配置、初始化 TLS、启动 HTTP/3 服务。
- `config/`：配置定义与默认配置文件。
- `handlers/`：HTTP/3 / WebSocket / 状态接口处理。
- `control/`：握手、注册、虚拟 IP 分配等核心控制逻辑。
- `protocol/`、`proto/`：协议定义与 protobuf 生成代码。

## 配置

默认读取 `config/config.json`（不存在时回退 `config.json`）。

示例：

```json
{
  "default_domain": "ms.net",
  "default_gateway_id": "default-gateway",
  "domains": {
    "ms.net": {
      "groups": {
        "sales": { "gateway": "10.26.0.1", "netmask": "255.255.255.0" },
        "marketing": { "gateway": "10.27.0.1", "netmask": "255.255.255.0" }
      }
    },
    "dev.net": {
      "groups": {
        "qa": { "gateway": "10.28.0.1", "netmask": "255.255.255.0" }
      }
    }
  },
  "listen_addr": ":4433",
  "autocert_http_addr": ":80",
  "autocert_email": "admin@example.com",
  "cert_cache_dir": "./cert-cache",
  "gateway_ca_path": "./gateway-ca.pem"
}
```

可选字段：

- `autocert_domain`：启用 `autocert` 时用于签发证书的域名。
- `autocert_http_addr`：内置 ACME `HTTP-01` challenge server 监听地址，默认 `:80`。
- `autocert_email`：ACME 账户联系邮箱，可选但推荐配置。
- `default_domain`：创建用户时未指定域名时使用，默认建议 `ms.net`。
- `default_gateway_id`：默认下发给客户端的 gateway 身份标识。control 只按这个 `gateway_id` 选择默认网关，实际地址来自 gateway 上报并持久化保存的 `gateway_id -> endpoint` 记录。
- `gateway_ticket_secret`：control 与 gateway 共享的密钥；control 用它对下发给客户端的 gateway ticket 做 HMAC-SHA256 签名，也用它校验 gateway 上报的 `GatewayReportRequest.signature`。
- `gateway_ca_path`：可选。若 gateway 的 QUIC fallback 使用私有 CA / 自签链，control 会读取这个 PEM 文件并把 CA PEM 附到下发给客户端的 QUIC channel 元数据中。
- `domains`：多域名配置，`domains.<domain>.groups.<group>` 对应子域配置，例如 `sales.ms.net`。
- `tls_cert_path` / `tls_key_path`：使用本地证书文件。
- `client_ca_path`：客户端 CA 文件路径（PEM）。
- `require_client_cert`：是否强制客户端证书校验（mTLS）。

## 环境变量（优先级高于配置文件）

- `CONFIG_PATH`
- `LISTEN_ADDR`
- `TLS_CERT` / `TLS_KEY`
- `AUTOCERT_DOMAIN`
- `AUTOCERT_HTTP_ADDR`
- `AUTOCERT_EMAIL`
- `CERT_CACHE_DIR`
- `TLS_CLIENT_CA`
- `TLS_REQUIRE_CLIENT_CERT`
- `LOG_LEVEL`
- `ADMIN_SOCKET_PATH`（管理员命令本地 Unix Domain Socket 路径，默认 `/tmp/sdl-control-admin.sock`）

## 使用 Makefile 编译与运行

```bash
cd sdl-control
make build
```

编译产物为当前目录下的 `./sdl-control`。

### 内置 ACME / 自动续期

当未提供 `TLS_CERT` / `TLS_KEY` 或 `tls_cert_path` / `tls_key_path` 时，`sdl-control` 会自动进入内置 ACME 模式：

- HTTP/3 控制面继续监听 `listen_addr`
- 同时额外启动一个 `HTTP-01` challenge server 在 `autocert_http_addr`（默认 `:80`）
- 证书与 ACME 账户缓存保存在 `cert_cache_dir`

最小要求：

- `autocert_domain` 指向当前 control 公网域名
- 该域名的 80 端口能到达 `sdl-control`
- `listen_addr` 对应的 HTTP/3 UDP 端口能被客户端访问

示例：

```bash
AUTOCERT_DOMAIN=control.example.com \
AUTOCERT_HTTP_ADDR=:80 \
AUTOCERT_EMAIL=admin@example.com \
LISTEN_ADDR=:4433 \
./sdl-control
```

如果你已经有现成证书，仍然可以继续走静态文件模式；只有在未提供证书文件时，才会切到内置 ACME。

常用命令：

```bash
make run     # 运行已编译二进制
make clean   # 删除二进制
make proto   # 重新生成 proto Go 代码（需安装 protoc 与插件）
```

会同时生成：

- `./sdl-control`
- `./sdl-admin`

## 管理员命令（sdl-admin）

`sdl-admin` 通过本机 Unix Domain Socket 调用控制端管理接口（默认 `/tmp/sdl-control-admin.sock`）。

示例：

```bash
./sdl-admin createUser --userId user1 --group sales.ms.net
./sdl-admin createUser -u user1
./sdl-admin issueDeviceTicket --userId <user_id>
./sdl-admin issueDeviceTicket -u <user_id> -g sales.ms.net
./sdl-admin listGateway
./sdl-admin registerGateway --gateway-id gw-1
```

说明：`createUser` 里的 `--group` 不传时默认是 `default`（最终会落成默认域名下的 `default.<domain>`）。`--group` 可传短名（如 `sales`，会自动补全为用户所属域名下的 `sales.<user-domain>`）；若传 FQDN（如 `sales.ms.net`），会校验其必须属于该用户所属域名。`issueDeviceTicket` 里的 `--group` 可省略，默认是 `default.ms.net`；`--ttlSeconds` 也可省略，默认是 `300`。

Gateway 注册/保活分为两层：

- **HMAC 鉴权**：gateway 每次发送 `GatewayReportRequest` 都必须携带 `nonce + signature`。signature 覆盖 `GatewayReportProof`（`gateway_id + capabilities + report_unix_ms + nonce + gateway_channels + default_gateway_channel + gateway_udp_public_key + gateway_udp_key_id` 的 protobuf 编码），由 control 使用 `gateway_ticket_secret` 做 HMAC-SHA256 校验；control 同时对 `report_unix_ms + nonce` 执行新鲜度/重放保护。
- **管理批准**：鉴权通过后，除配置中的 `default_gateway_id` 对应 gateway 外，其他 gateway 仍需先经 `sdl-admin registerGateway --gateway-id <id>` 批准，其 `GatewayReportRequest` 才会返回成功。默认 gateway 第一次成功上报后，control 会持久化保存该 `gateway_id` 当前的 `endpoint`，后续给客户端下发默认网关时直接读取这份映射。`sdl-admin listGateway` 可查看默认网关、待批准上报与已批准网关状态（含 `alive` 保活状态）。

control 对已批准网关采用租约保活（90 秒），并基于 `report_unix_ms + nonce` 做有限时间窗内的重放保护；超时未上报的网关不会继续被下发给客户端。

当前 gateway 下发模型是 channel-aware 的：

- `client -> gateway` 默认使用 UDP secure channel
- control 下发 `gateway_udp_public_key` / `gateway_udp_key_id` 给客户端完成 UDP bootstrap
- 若 gateway 同时上报 QUIC channel，control 也会把对应的 `server_name` 和可选 CA PEM 一并下发，供客户端做 QUIC fallback

设备认证（auth device）由 `sdl auth` 发起：客户端输入 `--userId`、可选 `--group`（默认 `default.ms.net`）和 `ticket` 发送到 `sdl-control`，认证成功后设备才可注册入网。

可选参数：

- `--socket <path>`：指定 socket 路径（也可用环境变量 `SDL_ADMIN_SOCKET`）。

## 验证

```bash
go test ./...
```

## 服务端镜像发布

仓库内置了 `release-image` workflow：

- tag push：发布 `ghcr.io/<owner>/sdl-control:<tag>`
- `workflow_dispatch`：可指定 `source_ref` 与 `release_tag`

这条 workflow 设计为给 `sdl-integration` 的 release gate 和 `sdl-deploy` 消费。

## 迁移方向（简要）

1. 继续补齐与 `vnts` 对齐的控制面协议行为（认证、注册、状态同步）。
2. 以 HTTP/3 `/control` + 证书校验作为控制面主链路。
3. 将数据转发能力下沉到可集群化的 gateway 服务，实现控制面与转发面独立扩缩容。
