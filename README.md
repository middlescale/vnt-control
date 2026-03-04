# vnt-control

`vnt-control` 是 `vnts` 的 Go 重写控制面项目，目标是将控制面与网关转发面解耦：客户端通过 QUIC 与控制服务通信完成认证与状态同步，数据转发由独立 gateway 集群负责。

## 目标架构分层

- `vnts` / `vnt-control`（Control Plane）：
  - 用户/设备认证
  - 注册与会话管理
  - 控制面在线状态、设备列表、NAT 信息等状态更新
- `gateway` 集群（Data Plane）：
  - 数据包转发与中继
  - 横向扩展与高可用
- `vnt` 客户端：
  - 通过 QUIC 与控制面交互
  - 按控制面下发信息选择/切换数据路径

## 在线状态语义（当前实现）

- `ControlOnline`：表示客户端是否与控制面保持活跃（注册、控制 ping、状态上报都会刷新）。
- `DataPlaneReachable`：表示数据面可达性（当前按 `ClientStatusInfo.p2p_list` 是否非空判定）。
- `DeviceStatus` 当前按 `ControlOnline` 对外映射：在线为 `0`，离线为 `1`。

> 说明：当前 `DataPlaneReachable` 语义是“P2P 可达”，尚未包含仅 relay/gateway 可达场景，后续会扩展。

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
  "default_domain": "ms.net",
  "default_gateway": "gateway.middlescale.net:433",
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
  "cert_cache_dir": "./cert-cache"
}
```

可选字段：

- `autocert_domain`：启用 `autocert` 时用于签发证书的域名。
- `default_domain`：创建用户时未指定域名时使用，默认建议 `ms.net`。
- `default_gateway`：无动态上报 gateway 时用于下发的默认网关地址，默认 `gateway.middlescale.net:433`。
- `domains`：多域名配置，`domains.<domain>.groups.<group>` 对应子域配置，例如 `sales.ms.net`。
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
- `ADMIN_SOCKET_PATH`（管理员命令本地 Unix Domain Socket 路径，默认 `/tmp/vnt-control-admin.sock`）

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

会同时生成：

- `./vnt-control`
- `./vnt-admin`

## 管理员命令（vnt-admin）

`vnt-admin` 通过本机 Unix Domain Socket 调用控制端管理接口（默认 `/tmp/vnt-control-admin.sock`）。

示例：

```bash
./vnt-admin --createUser user1 --domain ms.net
./vnt-admin --issueDeviceTicket --userId <user_id> --group sales.ms.net --ttlSeconds 300
./vnt-admin --issueDeviceTicket --userId <user_id> --group sales --ttlSeconds 300
./vnt-admin --list_gateway
./vnt-admin --register_gateway --gateway_id gw-1
```

说明：`--group` 可传短名（如 `sales`，会自动补全为用户所属域名下的 `sales.<user-domain>`）；若传 FQDN（如 `sales.ms.net`），会校验其必须属于该用户所属域名。

Gateway 注册后，control 会在客户端注册响应 `RegistrationResponse.gateway_access_grant` 下发可用 gateway 信息（endpoint/public_key/capabilities）与短期 ticket。除配置中的 `default_gateway` 外，其他 gateway 需先经 `vnt-admin --register_gateway --gateway_id <id>` 批准后，其 `GatewayReportRequest` 才会被接受。`vnt-admin --list_gateway` 可查看缺省网关、待批准上报与已批准网关状态（含 `alive` 保活状态）。control 对已批准网关采用租约保活（90 秒），超时未上报的网关不会继续被下发给客户端。

设备认证（auth device）由 `vnt-cli` 发起：客户端输入 `user_id/group/ticket` 发送到 `vnt-control`，认证成功后设备才可注册入网。

可选参数：

- `--socket <path>`：指定 socket 路径（也可用环境变量 `VNT_ADMIN_SOCKET`）。

## 验证

```bash
go test ./...
```

## 迁移方向（简要）

1. 继续补齐与 `vnts` 对齐的控制面协议行为（认证、注册、状态同步）。
2. 以 QUIC + 证书校验作为控制面主链路。
3. 将数据转发能力下沉到可集群化的 gateway 服务，实现控制面与转发面独立扩缩容。
