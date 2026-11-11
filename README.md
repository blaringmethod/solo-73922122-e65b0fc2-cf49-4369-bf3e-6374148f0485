# 防火墙变更上线前检查 · 凭据保管

两个功能：

1. **防火墙变更上线前检查**：精确对比**旧规则（当前线上）**与**新规则（待上线）**，
   逐条判断新规则中的每条 `allow` 是否放行了旧规则（含默认拒绝）所拒绝的流量。
2. **凭据保管**：安全运维轮换告警接入凭据的加密主密钥期间，连接配置凭据的
   加密存取服务。AES-256-GCM 加密、主密钥分文件持久化、在线轮换 + 后台逐条迁移，
   支持多进程并发读写。

## 快速开始

```bash
docker compose up --build
# 防火墙检查：  http://localhost:8000/      （备用入口 http://localhost:8001/）
# 凭据保管：    http://localhost:8000/vault （演示账户 ops / demo1234）
```

compose 会启动**两个服务进程**（app1:8000、app2:8001），共享同一数据卷
`vault-data`（SQLite + 主密钥文件），用于演示并发读写、轮换与迁移在多进程下
仍然成立：可以从 8000 写入、从 8001 读取，在任一进程发起轮换，两个进程
协作完成后台迁移。

本地开发（无需 Docker）：

```bash
pip install -r requirements.txt
VAULT_DATA_DIR=./data uvicorn app.main:app --host 0.0.0.0 --port 8000
# 再开一个进程（共享同一数据目录）：
VAULT_DATA_DIR=./data uvicorn app.main:app --host 0.0.0.0 --port 8001
```

运行测试：

```bash
python3 tests/test_exactness.py   # 防火墙差集：穷举交叉验证
python3 tests/test_vault.py       # 凭据保管：加密/轮换/并发/续迁
```

## 凭据保管

### 功能与限制

- 按**连接名**保存 / 读取 / 删除凭据，最多 **1000 条**，每条明文不超过 **4KiB**（UTF-8）；
- 仅**固定本地演示账户**可访问（默认 `ops` / `demo1234`，用环境变量
  `VAULT_USER` / `VAULT_PASSWORD` 覆盖），登录后签发 HMAC 会话 cookie（12 小时）；
- 页面展示当前密钥版本、密钥文件、轮换进度（已迁移 / 剩余），并可一键发起轮换；
- **凭据明文绝不入库、绝不写日志**：SQLite 中只保存 密文 + 随机 nonce + 密钥版本；
  日志只记录版本号、条数等元数据。

### 加密与存储

- `cryptography` 的 **AES-256-GCM**：每条凭据使用随机 12 字节 nonce，
  连接名作为附加认证数据（AAD），防止密文被改名挪用；
- SQLite（WAL 模式，多进程安全）表结构：`credentials(name, ciphertext, nonce,
  key_version, updated_at)`、`key_state(active_version)`、`rotation(...)`；
- **主密钥分文件持久保存**：每个版本一个文件 `keys/master_v{版本}.key`，
  经"临时文件 + fsync + link"原子创建，读者不会看到写了一半的密钥文件。

### 主密钥轮换协议

1. 点击轮换后，**先把新主密钥原子落盘**；落盘失败则不做任何变更，
   旧钥仍是当前钥，凭据照常可读；
2. 新钥保存成功后，在**单个事务**内启用新钥并登记轮换 —— 此后**新写入只用新钥**；
   `rotation` 表保证**同一时刻只允许一轮轮换**（进行中的轮换会拒绝新轮换，HTTP 409）；
3. **后台逐条迁移**旧记录：每条记录一个独立小事务，CAS 更新
   （`WHERE 版本/密文/nonce 均为读取时旧值`）——**迁移期间被更新的凭据不会被
   旧明文覆盖**；不使用整轮迁移锁，读写全程不暂停；
4. **进程中断后重启续迁**：每个进程的监督线程发现 `rotation` 表中有
   `running` 状态即继续迁移（迁移幂等，多进程可协作）；
5. 全部记录迁移完成后，**确认全库无旧钥引用（COUNT=0）才删除旧钥文件**；
   正在读取旧记录的请求仍可完成：本进程密钥缓存命中，或触发"行已迁移"
   重读后解密。

### API（均需登录，除 login）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/vault/login` | 登录 `{username, password}`，签发会话 cookie |
| POST | `/api/vault/logout` | 退出 |
| GET | `/api/vault/state` | 当前密钥版本、凭据计数、密钥文件、轮换进度 |
| GET | `/api/vault/credentials` | 列出连接名与元数据（不含明文） |
| POST | `/api/vault/credentials` | 保存 `{name, secret}`（新建或覆盖） |
| GET | `/api/vault/credentials/{name}` | 读取并解密一条凭据 |
| DELETE | `/api/vault/credentials/{name}` | 删除 |
| POST | `/api/vault/rotate` | 发起主密钥轮换（进行中返回 409） |

## 防火墙规则语义

- 每侧规则集是一个 JSON 数组，**最多 30 条**；
- 规则**按顺序匹配，首条命中生效**；未命中任何规则的流量**默认拒绝**；
- 每条规则字段：

| 字段 | 含义 | 取值 |
|---|---|---|
| `src` | 源地址 | IPv4 CIDR，如 `"10.0.0.0/8"`；单主机 `"10.0.0.1"`（=/32）；`"0.0.0.0/0"` 任意 |
| `dst` | 目的地址 | 同上 |
| `proto` | 协议 | `"tcp"` 或 `"udp"`（不区分大小写） |
| `ports` | 目的端口闭区间 | `[下界, 上界]`，如 `[80, 443]`；单端口可写 `[80, 80]` 或 `80`；范围 0–65535 |
| `action` | 动作 | `"allow"` 或 `"deny"` |
| `comment` | 备注（可选） | 字符串 |

示例：

```json
[
  {"src": "0.0.0.0/0", "dst": "10.0.0.10/32", "proto": "tcp", "ports": [443, 443],
   "action": "allow", "comment": "HTTPS"}
]
```

## 判定方法（精确，非抽样）

每条规则是 (源IP, 目的IP, 端口) 空间中的一个长方体，TCP/UDP 两个协议空间分别处理。
工具对新旧规则集做**长方体精确差集运算**，覆盖全部 2³² × 2³² × 65536 × 2 种组合，
**不使用任何抽样**：

1. 对每条新 `allow` 规则，求其**实际生效区域**＝自身矩形 − 顺序在前的所有新规则（首条匹配语义）；
2. 再减去旧规则集实际放行的区域（旧 allow 规则的生效区域之并）；
3. 剩余区域非空 ⇒ 该规则放开了旧规则（含默认拒绝）拒绝的流量，此时给出一个具体
   **witness**（源/目的 IP、协议、端口）以及该流量在**新旧两侧各自命中的规则**
   （旧侧可能是某条显式 `deny`，也可能是**默认拒绝**）。

多条规则联合覆盖（如两条 /24 合并为一条 /23）、规则顺序变化（含死规则被激活）
均被正确处理。`tests/test_exactness.py` 在小空间内用暴力枚举逐点验证了该算法与
全空间穷举完全等价。

非法输入（JSON 语法、缺字段、CIDR/端口/协议/动作非法、未知字段、超过 30 条等）
会**逐条定位到具体规则**并整体拒绝计算。

## API（防火墙检查）

- `GET /` — 防火墙检查页面
- `GET /vault` — 凭据保管页面
- `GET /api/example` — 一键载入的变更示例
- `POST /api/diff` — 请求体 `{"old": [...], "new": [...]}`

成功响应：

```json
{
  "ok": true,
  "findings": [
    {"rule_index": 2, "rule_text": "allow tcp 0.0.0.0/0 → 10.0.0.10/32 端口 80-443",
     "comment": "...", "opened": true,
     "witness": {"src": "0.0.0.0", "dst": "10.0.0.10", "proto": "tcp", "port": 81},
     "old_match": {"type": "default_deny"}}
  ],
  "stats": {"old_rules": 7, "new_rules": 6, "new_deny_rules": 1,
            "allow_rules_checked": 5, "opened_rules": 2}
}
```

`old_match` 为 `{"type": "rule", "rule_index": ..., "rule_text": ...}`（命中显式 deny）
或 `{"type": "default_deny"}`（未命中任何旧规则）。校验失败返回
`{"ok": false, "errors": [{"side": "old|new", "rule": 序号, "message": ...}]}`（HTTP 400）。

## 目录结构

```
app/
  firewall.py        # 防火墙核心：校验 + 长方体精确差集判定
  example.py         # 一键载入的变更示例
  vault.py           # 凭据核心：AES-GCM、密钥文件、轮换、后台迁移、旧钥清理
  vault_web.py       # 凭据 Web 接口：固定演示账户 + HMAC 会话
  main.py            # FastAPI 入口（两个功能 + 页面）
  static/index.html  # 防火墙检查页面
  static/vault.html  # 凭据保管页面（存取 + 轮换进度）
tests/test_exactness.py  # 防火墙：穷举交叉验证
tests/test_vault.py      # 凭据：加密/轮换/并发/续迁/清理
Dockerfile
docker-compose.yml       # 两个服务进程 + 共享数据卷
```
