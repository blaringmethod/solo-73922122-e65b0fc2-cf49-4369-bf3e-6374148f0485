# 防火墙变更上线前检查

给网络管理员使用的上线前检查工具：精确对比**旧规则（当前线上）**与**新规则（待上线）**，
逐条判断新规则中的每条 `allow` 是否放行了旧规则（含默认拒绝）所拒绝的流量，
找出“意外放开的流量”。

## 快速开始

```bash
docker compose up --build
# 打开 http://localhost:8000
```

本地开发（无需 Docker）：

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

运行正确性测试（穷举交叉验证，不依赖第三方库）：

```bash
python3 tests/test_exactness.py
```

## 规则语义

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

## API

- `GET /` — 页面
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
  firewall.py        # 核心：校验 + 长方体精确差集判定
  example.py         # 一键载入的变更示例
  main.py            # FastAPI 入口
  static/index.html  # 页面（粘贴/编辑两份规则、展示逐条判定）
tests/test_exactness.py  # 穷举交叉验证 + 示例与校验测试
Dockerfile
docker-compose.yml
```
