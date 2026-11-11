"""FastAPI 入口：防火墙变更差集计算接口 + 凭据保管页。"""

from __future__ import annotations

import ipaddress
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse

from .example import NEW_EXAMPLE, OLD_EXAMPLE
from .firewall import (ComplexityError, ValidationError, analyze,
                       validate_rulesets)
from .vault import MigrationSupervisor, Vault, load_or_create_secret
from .vault_web import create_router

logging.basicConfig(level=logging.INFO)

BASE_DIR = Path(__file__).resolve().parent

# 凭据保管库：数据目录（SQLite + 主密钥文件）通过环境变量配置，
# 多进程部署时指向同一共享卷。
DATA_DIR = Path(os.environ.get("VAULT_DATA_DIR", "./data"))
VAULT_USER = os.environ.get("VAULT_USER", "ops")
VAULT_PASSWORD = os.environ.get("VAULT_PASSWORD", "demo1234")

vault = Vault(DATA_DIR)
session_secret = load_or_create_secret(DATA_DIR / "keys" / "session.secret")
supervisor = MigrationSupervisor(vault)


@asynccontextmanager
async def lifespan(_app):
    supervisor.start()      # 后台迁移：进行中的轮换继续逐条迁移（含重启续迁）
    yield
    supervisor.stop()


app = FastAPI(title="防火墙变更上线前检查 · 凭据保管", lifespan=lifespan)
app.include_router(create_router(vault, VAULT_USER, VAULT_PASSWORD,
                                 session_secret))


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/vault", include_in_schema=False)
def vault_page():
    return FileResponse(BASE_DIR / "static" / "vault.html")


@app.get("/api/example")
def get_example():
    """一键载入的变更示例。"""
    return {"old": OLD_EXAMPLE, "new": NEW_EXAMPLE}


@app.post("/api/diff")
async def diff(request: Request):
    """对比新旧规则，逐条判定新 allow 规则是否放行了旧规则拒绝的流量。"""
    try:
        payload = await request.json()
    except Exception:
        return _error("请求体不是合法的 JSON", status=400)
    if not isinstance(payload, dict) or "old" not in payload or "new" not in payload:
        return _error('请求体必须是包含 "old" 和 "new" 两个字段的 JSON 对象',
                      status=400)

    try:
        old_rules, new_rules = validate_rulesets(payload["old"], payload["new"])
    except ValidationError as exc:
        return JSONResponse({"ok": False, "errors": exc.errors},
                            status_code=400)

    try:
        findings = analyze(old_rules, new_rules)
    except ComplexityError as exc:
        return _error(str(exc), status=422)

    opened = sum(1 for f in findings if f.opened)
    return {
        "ok": True,
        "findings": [_finding_json(f) for f in findings],
        "stats": {
            "old_rules": len(old_rules),
            "new_rules": len(new_rules),
            "new_deny_rules": sum(1 for r in new_rules if r.action == "deny"),
            "allow_rules_checked": len(findings),
            "opened_rules": opened,
        },
    }


def _error(message, status):
    return JSONResponse(
        {"ok": False, "errors": [{"side": None, "rule": None,
                                  "message": message}]},
        status_code=status)


def _finding_json(f):
    out = {
        "rule_index": f.rule.index + 1,
        "rule_text": f.rule.text(),
        "comment": f.rule.comment,
        "opened": f.opened,
    }
    if f.opened:
        src, dst, proto, port = f.witness
        out["witness"] = {
            "src": str(ipaddress.IPv4Address(src)),
            "dst": str(ipaddress.IPv4Address(dst)),
            "proto": proto,
            "port": port,
        }
        if f.old_match is None:
            out["old_match"] = {"type": "default_deny"}
        else:
            out["old_match"] = {
                "type": "rule",
                "rule_index": f.old_match.index + 1,
                "rule_text": f.old_match.text(),
                "comment": f.old_match.comment,
            }
    return out
