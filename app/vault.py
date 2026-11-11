"""凭据保管库核心：AES-GCM 加密、主密钥文件、在线轮换与后台迁移。

存储模型
- SQLite（WAL 模式，多进程共享）只保存：密文 + 随机 nonce + 密钥版本 + 更新时间，
  凭据明文只存在于内存，绝不入库、绝不写日志；
- 每个版本的主密钥单独一个文件 keys/master_v{版本}.key，原子创建（临时文件 + link），
  读者永远只能看到完整文件；
- 密文以连接名作为 AES-GCM 的附加认证数据（AAD），防止密文被改名挪用。

轮换协议（同一时刻只允许一轮，由 rotation 单行表 + 事务保证）
1. 生成新钥并原子落盘 —— 新钥保存成功之前不改变任何状态，失败时旧钥仍是当前钥，
   凭据照常可读；
2. 单个事务内：校验无进行中的轮换 → 启用新钥（active_version = 新版本）→ 登记轮换；
   此后新写入只使用新钥；
3. 后台逐条迁移旧记录：每条记录一个独立小事务，CAS 更新
   （WHERE 密钥版本/密文/nonce 均为读取时的旧值），迁移期间被用户更新的记录
   不会被旧明文覆盖；读写全程不被整轮迁移锁阻塞；
4. 进程中断后重启：监督线程发现 rotation 表中有 running 状态即续迁（迁移幂等）；
5. 全部记录迁移完成后才确认无旧钥引用（COUNT=0），再删除旧钥文件；
   正在读取旧记录的请求：本进程密钥缓存仍可用，或触发"行已迁移"重读，
   两种路径都能完成请求。
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger("vault")

MAX_RECORDS = 1000            # 凭据条数上限
MAX_SECRET_BYTES = 4096       # 每条凭据明文上限：4 KiB（UTF-8 编码后）
MAX_NAME_CHARS = 128
NONCE_SIZE = 12               # AES-GCM 标准 nonce
KEY_SIZE = 32                 # AES-256-GCM

_KEY_FILE_RE = re.compile(r"^master_v(\d+)\.key$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
    name        TEXT PRIMARY KEY,
    ciphertext  BLOB    NOT NULL,
    nonce       BLOB    NOT NULL,
    key_version INTEGER NOT NULL,
    updated_at  REAL    NOT NULL
);
CREATE TABLE IF NOT EXISTS key_state (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    active_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rotation (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    from_version   INTEGER NOT NULL,
    to_version     INTEGER NOT NULL,
    status         TEXT    NOT NULL CHECK (status IN ('running', 'done')),
    started_at     REAL    NOT NULL,
    finished_at    REAL,
    migrated_count INTEGER NOT NULL DEFAULT 0
);
"""


class VaultError(Exception):
    """业务错误，message 可直接展示给操作员（不含任何凭据明文）。"""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


class KeyFileMissing(Exception):
    """某版本密钥文件不存在（通常因旧钥已被清理，对应记录应已迁移）。"""

    def __init__(self, version: int):
        super().__init__(f"master key v{version} file missing")
        self.version = version


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create_file_atomic(path: Path, data: bytes) -> bool:
    """原子地排他创建文件：已存在则返回 False 且原内容不变。

    先写临时文件并 fsync，再用 link(2) 落到目标名 —— 其他进程要么看不到，
    要么看到完整内容，绝不会读到写了一半的文件。
    """
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{threading.get_ident()}")
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        try:
            os.link(tmp, path)
        except FileExistsError:
            return False
        _fsync_dir(path.parent)
        return True
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def load_or_create_secret(path: Path, size: int = KEY_SIZE) -> bytes:
    """读取持久化的随机秘密；不存在则原子创建（多进程并发安全）。"""
    try:
        data = path.read_bytes()
        if len(data) == size:
            return data
        raise VaultError(f"秘密文件损坏：{path.name}", 500)
    except FileNotFoundError:
        pass
    secret = os.urandom(size)
    if create_file_atomic(path, secret):
        return secret
    # 并发下另一进程已创建：采用文件内容
    data = path.read_bytes()
    if len(data) != size:
        raise VaultError(f"秘密文件损坏：{path.name}", 500)
    return data


class Vault:
    """凭据保管库。一个进程一个实例；多实例可安全共享同一数据目录。"""

    def __init__(self, data_dir, max_records: int = MAX_RECORDS):
        self.data_dir = Path(data_dir)
        self.key_dir = self.data_dir / "keys"
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / "vault.db"
        self.max_records = max_records
        self._key_cache: dict[int, bytes] = {}
        self._cache_lock = threading.Lock()
        self._init_db()
        self._bootstrap()

    # ------------------------------------------------------------------
    # 基础设施
    # ------------------------------------------------------------------

    @contextmanager
    def _db(self, write: bool = False):
        """短连接；write=True 时以 BEGIN IMMEDIATE 开启写事务（跨进程串行化写者）。"""
        conn = sqlite3.connect(self.db_path, timeout=15, isolation_level=None)
        try:
            conn.execute("PRAGMA busy_timeout=15000")
            if write:
                conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except Exception:
                if write:
                    conn.execute("ROLLBACK")
                raise
            else:
                if write:
                    conn.execute("COMMIT")
        finally:
            conn.close()

    def _init_db(self) -> None:
        # executescript 会自行管理事务，这里不开显式写事务
        with self._db() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)

    def _bootstrap(self) -> None:
        """首次启动：生成 v1 主密钥并落库。多进程并发由写事务串行化。"""
        with self._db(write=True) as conn:
            row = conn.execute(
                "SELECT active_version FROM key_state WHERE id = 1").fetchone()
            if row:
                return
            key = load_or_create_secret(self._key_path(1))
            conn.execute(
                "INSERT INTO key_state (id, active_version) VALUES (1, 1)")
            with self._cache_lock:
                self._key_cache[1] = key
            log.info("已初始化主密钥 v1")

    # ------------------------------------------------------------------
    # 密钥文件
    # ------------------------------------------------------------------

    def _key_path(self, version: int) -> Path:
        return self.key_dir / f"master_v{version}.key"

    def _load_key(self, version: int) -> bytes:
        with self._cache_lock:
            key = self._key_cache.get(version)
        if key is not None:
            return key
        try:
            data = self._key_path(version).read_bytes()
        except FileNotFoundError:
            raise KeyFileMissing(version)
        if len(data) != KEY_SIZE:
            raise VaultError(f"主密钥文件损坏：版本 {version}", 500)
        with self._cache_lock:
            self._key_cache.setdefault(version, data)
        return data

    def _key_files_on_disk(self) -> list[int]:
        out = []
        for f in self.key_dir.glob("master_v*.key"):
            m = _KEY_FILE_RE.match(f.name)
            if m:
                out.append(int(m.group(1)))
        return sorted(out)

    # ------------------------------------------------------------------
    # 状态查询
    # ------------------------------------------------------------------

    @staticmethod
    def _active_version(conn) -> int:
        row = conn.execute(
            "SELECT active_version FROM key_state WHERE id = 1").fetchone()
        if row is None:
            raise VaultError("主密钥尚未初始化", 500)
        return row[0]

    @staticmethod
    def _rotation_row(conn) -> dict | None:
        row = conn.execute(
            "SELECT from_version, to_version, status, started_at, finished_at,"
            "       migrated_count FROM rotation WHERE id = 1").fetchone()
        if row is None:
            return None
        return {
            "from_version": row[0],
            "to_version": row[1],
            "status": row[2],
            "started_at": row[3],
            "finished_at": row[4],
            "migrated_count": row[5],
        }

    def status(self) -> dict:
        with self._db() as conn:
            active = self._active_version(conn)
            rot = self._rotation_row(conn)
            total = conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
            if rot and rot["status"] == "running":
                rot["remaining"] = conn.execute(
                    "SELECT COUNT(*) FROM credentials WHERE key_version < ?",
                    (rot["to_version"],)).fetchone()[0]
            elif rot:
                rot["remaining"] = 0
        return {
            "active_version": active,
            "records": total,
            "max_records": self.max_records,
            "max_secret_bytes": MAX_SECRET_BYTES,
            "keys_on_disk": self._key_files_on_disk(),
            "rotation": rot,
        }

    # ------------------------------------------------------------------
    # 凭据读写（轮换期间照常可用）
    # ------------------------------------------------------------------

    @staticmethod
    def _check_name(name) -> str:
        if not isinstance(name, str):
            raise VaultError("连接名必须是字符串")
        if not name:
            raise VaultError("连接名不能为空")
        if len(name) > MAX_NAME_CHARS:
            raise VaultError(f"连接名过长（超过 {MAX_NAME_CHARS} 字符）")
        if any(ord(c) < 32 or ord(c) == 127 for c in name):
            raise VaultError("连接名不能包含控制字符")
        if any(c in name for c in '/\\?#%'):
            raise VaultError("连接名不能包含 / \\ ? # % 字符")
        return name

    def save(self, name: str, secret: str) -> None:
        """新建或覆盖一条凭据；始终使用当前启用的主密钥加密。"""
        name = self._check_name(name)
        if not isinstance(secret, str):
            raise VaultError("凭据内容必须是字符串")
        data = secret.encode("utf-8")
        if len(data) > MAX_SECRET_BYTES:
            raise VaultError(
                f"凭据内容 {len(data)} 字节，超过 4KiB（{MAX_SECRET_BYTES} 字节）上限")
        with self._db(write=True) as conn:
            version = self._active_version(conn)
            exists = conn.execute(
                "SELECT 1 FROM credentials WHERE name = ?", (name,)).fetchone()
            if not exists:
                n = conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
                if n >= self.max_records:
                    raise VaultError(
                        f"凭据数量已达上限 {self.max_records} 条", 409)
            key = self._load_key(version)
            nonce = os.urandom(NONCE_SIZE)
            ct = AESGCM(key).encrypt(nonce, data, name.encode("utf-8"))
            conn.execute(
                "INSERT INTO credentials (name, ciphertext, nonce, key_version,"
                "                    updated_at)"
                " VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(name) DO UPDATE SET"
                "   ciphertext = excluded.ciphertext, nonce = excluded.nonce,"
                "   key_version = excluded.key_version,"
                "   updated_at = excluded.updated_at",
                (name, ct, nonce, version, time.time()))

    def _fetch_row(self, name: str):
        with self._db() as conn:
            return conn.execute(
                "SELECT name, ciphertext, nonce, key_version FROM credentials"
                " WHERE name = ?", (name,)).fetchone()

    def read(self, name: str) -> str:
        row = self._fetch_row(name)
        if row is None:
            raise VaultError("连接不存在", 404)
        return self._decrypt_row(row)

    def _decrypt_row(self, row, retries: int = 3) -> str:
        """按记录自身的密钥版本解密。

        若旧钥文件刚被清理（说明该记录已被迁移），重新读取该行再解密，
        保证"正在读取旧记录"的请求能够完成。
        """
        for _ in range(retries):
            name, ct, nonce, version = row
            try:
                key = self._load_key(version)
            except KeyFileMissing:
                fresh = self._fetch_row(name)
                if fresh is None:
                    raise VaultError("连接不存在", 404)
                row = fresh
                continue
            try:
                data = AESGCM(key).decrypt(nonce, ct, name.encode("utf-8"))
            except InvalidTag:
                raise VaultError("凭据解密失败：数据完整性校验未通过", 500)
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                raise VaultError("凭据内容不是合法 UTF-8", 500)
        raise VaultError("凭据读取失败：密钥版本正在迁移，请重试", 503)

    def list(self) -> list[dict]:
        """仅返回元数据，绝不含明文。"""
        with self._db() as conn:
            rows = conn.execute(
                "SELECT name, key_version, updated_at, length(ciphertext)"
                " FROM credentials ORDER BY name").fetchall()
        return [{"name": r[0], "key_version": r[1], "updated_at": r[2],
                 "size": r[3]} for r in rows]

    def delete(self, name: str) -> bool:
        with self._db(write=True) as conn:
            n = conn.execute(
                "DELETE FROM credentials WHERE name = ?", (name,)).rowcount
        return n > 0

    # ------------------------------------------------------------------
    # 轮换：先落盘新钥，再单事务启用；同一时刻只允许一轮
    # ------------------------------------------------------------------

    def start_rotation(self) -> dict:
        with self._db() as conn:
            current = self._active_version(conn)
            rot = self._rotation_row(conn)
        if rot and rot["status"] == "running":
            raise VaultError(
                f"已有轮换正在进行（v{rot['from_version']} → "
                f"v{rot['to_version']}），请等待完成", 409)

        new_version = current + 1
        # 第一步：新主密钥原子落盘。失败则到此为止 —— 旧钥仍是当前钥，凭据可读。
        try:
            new_key = load_or_create_secret(self._key_path(new_version))
        except OSError as exc:
            raise VaultError(
                f"新主密钥保存失败（{exc.strerror or exc}），未做任何变更", 500)

        # 第二步：单事务启用（校验无并发轮换 + 切换当前版本 + 登记轮换）。
        with self._db(write=True) as conn:
            cur = self._active_version(conn)
            rot = self._rotation_row(conn)
            if rot and rot["status"] == "running":
                raise VaultError("已有轮换正在进行，请等待完成", 409)
            if cur != current:
                raise VaultError("密钥版本已变化，请重试", 409)
            conn.execute(
                "UPDATE key_state SET active_version = ? WHERE id = 1",
                (new_version,))
            conn.execute(
                "INSERT INTO rotation (id, from_version, to_version, status,"
                "                    started_at, finished_at, migrated_count)"
                " VALUES (1, ?, ?, 'running', ?, NULL, 0)"
                " ON CONFLICT(id) DO UPDATE SET"
                "   from_version = excluded.from_version,"
                "   to_version = excluded.to_version,"
                "   status = 'running', started_at = excluded.started_at,"
                "   finished_at = NULL, migrated_count = 0",
                (current, new_version, time.time()))
        with self._cache_lock:
            self._key_cache[new_version] = new_key
        log.info("主密钥轮换已开始：v%d → v%d", current, new_version)
        return {"from_version": current, "to_version": new_version}

    # ------------------------------------------------------------------
    # 后台迁移：逐条、独立小事务、CAS 不覆盖并发更新；幂等可续迁
    # ------------------------------------------------------------------

    def migrate_batch(self, limit: int = 10) -> int:
        """迁移至多 limit 条旧版本记录，返回实际迁移条数（0 表示无可迁）。"""
        with self._db() as conn:
            rot = self._rotation_row(conn)
            if not rot or rot["status"] != "running":
                return 0
            to_version = rot["to_version"]
            names = [r[0] for r in conn.execute(
                "SELECT name FROM credentials WHERE key_version < ?"
                " ORDER BY name LIMIT ?", (to_version, limit))]
        moved = 0
        for name in names:
            if self._migrate_one(name, to_version):
                moved += 1
        return moved

    def _migrate_one(self, name: str, to_version: int) -> bool:
        row = self._fetch_row(name)
        if row is None:
            return False
        _, ct, nonce, version = row
        if version >= to_version:
            return False  # 已是新版本（可能被并发写入更新过）
        try:
            old_key = self._load_key(version)
        except KeyFileMissing:
            # 有记录引用就不会清理旧钥文件；出现即数据不一致
            raise VaultError(f"迁移失败：版本 {version} 的主密钥文件缺失", 500)
        new_key = self._load_key(to_version)
        aad = name.encode("utf-8")
        data = AESGCM(old_key).decrypt(nonce, ct, aad)
        new_nonce = os.urandom(NONCE_SIZE)
        new_ct = AESGCM(new_key).encrypt(new_nonce, data, aad)
        del data
        with self._db(write=True) as conn:
            # CAS：仅当记录仍保持读取时的版本/密文/nonce 才替换，
            # 迁移期间被用户更新的记录不会被旧明文覆盖。
            cur = conn.execute(
                "UPDATE credentials SET ciphertext = ?, nonce = ?, key_version = ?"
                " WHERE name = ? AND key_version = ? AND ciphertext = ?"
                "   AND nonce = ?",
                (new_ct, new_nonce, to_version, name, version, ct, nonce)
            ).rowcount
            if cur:
                conn.execute(
                    "UPDATE rotation SET migrated_count = migrated_count + 1"
                    " WHERE id = 1 AND status = 'running'")
        return bool(cur)

    def maybe_finalize(self) -> bool:
        """全部记录迁完后收尾：标记完成并清理无引用的旧钥文件。"""
        with self._db(write=True) as conn:
            rot = self._rotation_row(conn)
            if not rot or rot["status"] != "running":
                return False
            remaining = conn.execute(
                "SELECT COUNT(*) FROM credentials WHERE key_version < ?",
                (rot["to_version"],)).fetchone()[0]
            if remaining:
                return False
            done = conn.execute(
                "UPDATE rotation SET status = 'done', finished_at = ?"
                " WHERE id = 1 AND status = 'running'", (time.time(),)).rowcount
        if done:
            log.info("主密钥轮换完成：v%d → v%d",
                     rot["from_version"], rot["to_version"])
            self.cleanup_keys()
        return bool(done)

    def cleanup_keys(self) -> list[int]:
        """删除低于当前版本且全库无任何记录引用的旧钥文件。

        只清理 v < active：更高版本的文件可能正被另一进程的轮换准备使用。
        确认无引用（COUNT=0）后才删除；正在读取旧记录的请求由
        _decrypt_row 的重读机制保证完成。
        """
        with self._db() as conn:
            active = self._active_version(conn)
            referenced = {r[0] for r in conn.execute(
                "SELECT DISTINCT key_version FROM credentials")}
        removed = []
        for version in self._key_files_on_disk():
            if version >= active or version in referenced:
                continue
            try:
                self._key_path(version).unlink()
                removed.append(version)
                log.info("已移除无引用的旧主密钥文件：v%d", version)
            except FileNotFoundError:
                pass
        return removed


class MigrationSupervisor:
    """每进程一个的后台迁移监督线程。

    发现 rotation 表中有 running 状态的轮换即协作逐条迁移（多进程并发安全），
    全部迁完后收尾清理。进程重启后自动续迁。
    """

    def __init__(self, vault: Vault, batch: int = 10,
                 busy_interval: float = 0.25, idle_interval: float = 1.0):
        self.vault = vault
        self.batch = batch
        self.busy_interval = busy_interval
        self.idle_interval = idle_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="vault-migration", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                moved = self.vault.migrate_batch(self.batch)
                if moved:
                    self._stop.wait(self.busy_interval)
                else:
                    self.vault.maybe_finalize()
                    self._stop.wait(self.idle_interval)
            except Exception:
                log.exception("凭据迁移后台任务出错，稍后重试")
                self._stop.wait(2.0)
