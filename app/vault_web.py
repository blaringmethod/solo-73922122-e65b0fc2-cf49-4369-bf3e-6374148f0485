"""凭据保管页 Web 接口：固定本地演示账户 + HMAC 签名会话 cookie。

安全约定：
- 仅 /api/vault/login 公开，其余接口一律要求有效会话；
- 口令比较使用恒定时间比较；会话秘密持久化在共享数据目录，多进程通用；
- 任何日志与错误响应都不包含凭据明文。
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .vault import Vault, VaultError

log = logging.getLogger("vault.web")

SESSION_COOKIE = "vault_session"
SESSION_TTL = 12 * 3600  # 12 小时


def create_router(vault: Vault, user: str, password: str,
                  session_secret: bytes) -> APIRouter:
    router = APIRouter(prefix="/api/vault")

    def _sign(payload: str) -> str:
        return hmac.new(session_secret, payload.encode(),
                        hashlib.sha256).hexdigest()

    def _make_cookie() -> str:
        payload = str(int(time.time()) + SESSION_TTL)
        return f"{payload}.{_sign(payload)}"

    def _check_cookie(request: Request) -> bool:
        raw = request.cookies.get(SESSION_COOKIE, "")
        try:
            payload, sig = raw.rsplit(".", 1)
        except ValueError:
            return False
        if not hmac.compare_digest(sig, _sign(payload)):
            return False
        try:
            return int(payload) > time.time()
        except ValueError:
            return False

    def _err(message: str, status: int = 400) -> JSONResponse:
        return JSONResponse({"ok": False, "error": message},
                            status_code=status)

    def _deny(request: Request) -> JSONResponse | None:
        if not _check_cookie(request):
            return _err("未登录或会话已过期", 401)
        return None

    @router.post("/login")
    async def login(request: Request):
        try:
            body = await request.json()
        except Exception:
            return _err("请求体不是合法 JSON")
        username = body.get("username")
        passwd = body.get("password")
        if not isinstance(username, str) or not isinstance(passwd, str):
            return _err("字段 username 与 password 必须是字符串")
        ok = (hmac.compare_digest(username, user)
              and hmac.compare_digest(passwd, password))
        if not ok:
            log.warning("凭据保管页登录失败：用户 %r", username)
            return _err("用户名或密码错误", 403)
        resp = JSONResponse({"ok": True, "user": user})
        resp.set_cookie(SESSION_COOKIE, _make_cookie(), max_age=SESSION_TTL,
                        httponly=True, samesite="lax")
        return resp

    @router.post("/logout")
    def logout():
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(SESSION_COOKIE)
        return resp

    @router.get("/state")
    def state(request: Request):
        if (deny := _deny(request)) is not None:
            return deny
        return {"ok": True, "user": user, **vault.status()}

    @router.get("/credentials")
    def list_credentials(request: Request):
        if (deny := _deny(request)) is not None:
            return deny
        return {"ok": True, "items": vault.list()}

    @router.post("/credentials")
    async def save_credential(request: Request):
        if (deny := _deny(request)) is not None:
            return deny
        try:
            body = await request.json()
        except Exception:
            return _err("请求体不是合法 JSON")
        try:
            vault.save(body.get("name"), body.get("secret"))
        except VaultError as exc:
            return _err(exc.message, exc.status)
        return {"ok": True}

    @router.get("/credentials/{name}")
    def read_credential(name: str, request: Request):
        if (deny := _deny(request)) is not None:
            return deny
        try:
            secret = vault.read(name)
        except VaultError as exc:
            return _err(exc.message, exc.status)
        return {"ok": True, "name": name, "secret": secret}

    @router.delete("/credentials/{name}")
    def delete_credential(name: str, request: Request):
        if (deny := _deny(request)) is not None:
            return deny
        if not vault.delete(name):
            return _err("连接不存在", 404)
        return {"ok": True}

    @router.post("/rotate")
    def rotate(request: Request):
        if (deny := _deny(request)) is not None:
            return deny
        try:
            info = vault.start_rotation()
        except VaultError as exc:
            return _err(exc.message, exc.status)
        return {"ok": True, **info}

    return router
