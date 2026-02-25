# SubAdmin

一个可自托管的订阅管理项目，包含：

- Go 后端 API（登录、上游 CRUD、节点 CRUD、同步、输出、备份）
- React 管理后台（`/admin`）
- SQLite 持久化
- Subconverter/Sublink 容器集成
- Caddy 反向代理与 HTTPS

支持两种部署模式：

- 共存模式（推荐给已在主机跑 233boy/sing-box 脚本的场景）：不启用本项目 Caddy，不占用 80/443
- 网关模式：启用本项目 Caddy，统一提供 `/admin`、`/api`、`/clash`、`/singbox`

## 目录结构

- `backend/`: Go API 服务
- `web/`: React 管理后台
- `caddy/`: Caddy 配置
- `docker-compose.yml`: 一键部署
- `项目实现进度.md`: 当前实施与进度主文档

## 快速启动

1. 准备环境变量：

```bash
cp .env.example .env
```

2. 选择启动模式：

### 模式 A：共存模式（不占 80/443）

适用于你已经在 VPS 主机上运行 233boy/sing-box 脚本，并且 80/443 可能已被占用。

```bash
docker compose up -d --build api web sublink
```

默认端口（可在 `.env` 调整）：

- Web：`http://<server-ip>:18081`
- API：`http://<server-ip>:18080`
- 固定输出：`http://<server-ip>:18081/clash`、`http://<server-ip>:18081/singbox`

### 模式 B：网关模式（启用 Caddy）

```bash
docker compose --profile gateway up -d --build
```

访问：

- 管理后台：`https://<your-domain>/admin`
- Clash 输出：`https://<your-domain>/clash`
- Sing-box 输出：`https://<your-domain>/singbox`

本地测试可用 `DOMAIN=localhost`。

## 默认账号

- 用户名：`admin`
- 密码：`admin123`

请在 `.env` 中修改 `ADMIN_PASSWORD` 和 `JWT_SECRET`。

## 后端 API 概览

- 认证：
  - `POST /api/login`
  - `POST /api/logout`
  - `GET /api/me`
  - `PUT /api/password`
- 上游：
  - `GET /api/upstreams`
  - `POST /api/upstreams`
  - `PUT /api/upstreams/{id}`
  - `DELETE /api/upstreams/{id}`
  - `POST /api/upstreams/{id}/sync`
  - `POST /api/sync`
- 手动节点：
  - `GET /api/nodes`
  - `POST /api/nodes`
  - `PUT /api/nodes/{id}`
  - `DELETE /api/nodes/{id}`
- 设置：
  - `GET /api/settings`
  - `PUT /api/settings`
- 备份：
  - `GET /api/backup/export`
  - `POST /api/backup/import`
- 固定输出：
  - `GET /clash`
  - `GET /singbox`

## 实现说明

- 默认启用缓存模式：定时同步上游并写入本地缓存文件，再提供固定输出。
- 关闭缓存模式后，访问 `/clash`、`/singbox` 时实时拉取上游并转换。
- 当 `SUBLINK_URL` 不可用时，后端会返回 fallback 内容，避免接口完全不可用。

## 与主机 sing-box 脚本共存注意事项

- `api` 服务已配置 `host.docker.internal:host-gateway`，容器可访问主机服务。
- 如果你的上游地址写成 `127.0.0.1` 或 `localhost`，容器内无法访问，请改为：
  - 主机域名（推荐），例如 `https://your-domain/sub`
  - 或 `http://host.docker.internal:<port>/...`
- 你当前场景建议直接使用“模式 A 共存模式”。

## 已知限制

- 当前实现聚焦 MVP + 部分增强特性（同步、缓存、备份）；日志可先通过容器日志查看。
- 本环境中未安装 `go` / `npm`，无法在本机执行编译校验，建议通过 Docker 构建验证。
