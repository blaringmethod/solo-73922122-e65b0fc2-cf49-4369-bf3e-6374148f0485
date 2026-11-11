"""凭据保管库测试：加密存储、轮换、并发迁移、断点续迁、旧钥清理。

运行：python3 tests/test_vault.py
"""

import os
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.vault import (KEY_SIZE, MAX_SECRET_BYTES, MigrationSupervisor, Vault,
                       VaultError)


def new_vault(max_records=1000):
    d = tempfile.mkdtemp(prefix="vault-test-")
    return Vault(d, max_records=max_records), d


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def expect_vault_error(fn, status, msg):
    try:
        fn()
    except VaultError as e:
        check(e.status == status, f"{msg}：状态码应为 {status}，实际 {e.status}（{e.message}）")
        return
    raise AssertionError(f"{msg}：应抛出 VaultError({status})")


def db_bytes(d):
    out = b""
    for f in Path(d).glob("vault.db*"):
        out += f.read_bytes()
    return out


def key_versions_on_disk(d):
    return sorted(int(p.stem.removeprefix("master_v"))
                  for p in (Path(d) / "keys").glob("master_v*.key"))


def record_version(d, name):
    conn = sqlite3.connect(Path(d) / "vault.db")
    try:
        row = conn.execute(
            "SELECT key_version FROM credentials WHERE name=?", (name,)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def drain(vault, rounds=200):
    """驱动迁移直到收尾完成。"""
    for _ in range(rounds):
        vault.migrate_batch(50)
        if vault.maybe_finalize():
            return True
    return False


# ---------------------------------------------------------------------------

def test_roundtrip_and_no_plaintext_at_rest():
    v, d = new_vault()
    secret = "Pa55w0rd！连接凭据\n第二行 " + "x" * 100
    v.save("db-prod", secret)
    check(v.read("db-prod") == secret, "读取应还原明文")
    check(secret.encode() not in db_bytes(d), "数据库文件中不得出现明文")
    check("db-prod".encode() in db_bytes(d), "连接名（非秘密）应出现在库中")
    items = v.list()
    check(items[0]["key_version"] == 1, "初始密钥版本应为 1")
    check(key_versions_on_disk(d) == [1], "磁盘上应只有 v1 密钥文件")
    print("ok 加密存取往返，明文不落盘")


def test_limits():
    v, d = new_vault(max_records=3)
    v.save("a", "x" * MAX_SECRET_BYTES)            # 恰好 4KiB 允许
    expect_vault_error(lambda: v.save("b", "x" * (MAX_SECRET_BYTES + 1)),
                       400, "超过 4KiB 应拒绝")
    expect_vault_error(lambda: v.save("", "s"), 400, "空连接名应拒绝")
    expect_vault_error(lambda: v.save("bad\nname", "s"), 400, "控制字符应拒绝")
    expect_vault_error(lambda: v.save("a/b", "s"), 400, "斜杠应拒绝")
    expect_vault_error(lambda: v.save("n" * 129, "s"), 400, "超长连接名应拒绝")
    v.save("b", "s"); v.save("c", "s")
    expect_vault_error(lambda: v.save("d", "s"), 409, "超过条数上限应拒绝")
    v.save("a", "s2")  # 更新已有连接不占新额度
    check(v.read("a") == "s2", "更新后应读到新值")
    print("ok 4KiB / 条数上限 / 连接名校验")


def test_rotation_basic():
    v, d = new_vault()
    for i in range(20):
        v.save(f"conn-{i}", f"secret-{i}")
    info = v.start_rotation()
    check(info == {"from_version": 1, "to_version": 2}, "轮换应推进到 v2")
    st = v.status()
    check(st["active_version"] == 2, "轮换后当前版本应为 2")
    check(st["rotation"]["status"] == "running", "轮换应处于 running")
    check(st["rotation"]["remaining"] == 20, "20 条待迁移")
    check(key_versions_on_disk(d) == [1, 2], "轮换期间新旧钥文件都应存在")

    # 迁移进行中：新旧记录都可读；新写入只用新钥
    v.migrate_batch(5)
    check(v.read("conn-0") == "secret-0", "迁移期间旧记录可读")
    v.save("conn-new", "brand-new")
    check(record_version(d, "conn-new") == 2, "新写入必须使用新钥")

    check(drain(v), "迁移应能完成")
    st = v.status()
    check(st["rotation"]["status"] == "done", "轮换应已完成")
    check(all(record_version(d, f"conn-{i}") == 2 for i in range(20)),
          "全部记录应迁移到 v2")
    check(key_versions_on_disk(d) == [2], "确认无引用后旧钥文件应被移除")
    for i in range(20):
        check(v.read(f"conn-{i}") == f"secret-{i}", "迁移后全部可读")
    check(v.read("conn-new") == "brand-new", "迁移期间写入的记录可读")
    print("ok 轮换：先启用新钥、后台迁移、旧钥确认无引用后移除")


def test_only_one_rotation_at_a_time():
    v, d = new_vault()
    v.save("a", "1")
    v.start_rotation()
    expect_vault_error(v.start_rotation, 409, "轮换进行中不得再次轮换")
    drain(v)
    info = v.start_rotation()  # 完成后可以再轮换
    check(info["to_version"] == 3, "完成后应能继续轮换到 v3")
    drain(v)
    check(v.read("a") == "1", "多轮轮换后数据仍正确")
    check(key_versions_on_disk(d) == [3], "最终只保留当前密钥文件")
    print("ok 同一时刻只允许一轮轮换")


def test_migration_never_overwrites_concurrent_update():
    v, d = new_vault()
    v.save("hot", "old-value")
    v.start_rotation()
    # 迁移尚未触碰该记录时，用户更新为新值（用新钥加密）
    v.save("hot", "new-value")
    check(record_version(d, "hot") == 2, "更新应使用新钥")
    drain(v)
    check(v.read("hot") == "new-value", "迁移不得覆盖迁移期间的更新")

    # 直接验证 CAS：拿着旧密文的迁移写，在记录被更新后必须失效
    v2, d2 = new_vault()
    v2.save("k", "v1")
    conn = sqlite3.connect(Path(d2) / "vault.db")
    row = conn.execute(
        "SELECT ciphertext, nonce, key_version FROM credentials WHERE name='k'"
    ).fetchone()
    conn.close()
    v2.save("k", "v2")  # 并发更新
    with v2._db(write=True) as c:
        n = c.execute(
            "UPDATE credentials SET ciphertext=?, nonce=?, key_version=?"
            " WHERE name=? AND key_version=? AND ciphertext=? AND nonce=?",
            (b"x", b"y", 9, "k", row[2], row[0], row[1])).rowcount
    check(n == 0, "CAS 必须拒绝基于旧密文的写入")
    check(v2.read("k") == "v2", "并发更新后的值必须保留")
    print("ok 迁移不覆盖期间更新的凭据（CAS 生效）")


def test_restart_resumes_migration():
    v1, d = new_vault()
    for i in range(30):
        v1.save(f"c{i}", f"s{i}")
    v1.start_rotation()
    v1.migrate_batch(7)  # 迁移一部分后“进程崩溃”
    del v1

    v2 = Vault(d)  # 重启：新实例发现 running 轮换，续迁
    st = v2.status()
    check(st["rotation"]["status"] == "running", "重启后轮换应仍为 running")
    check(st["active_version"] == 2, "重启后当前版本应保持 v2")
    check(drain(v2), "重启后续迁应能完成")
    check(all(record_version(d, f"c{i}") == 2 for i in range(30)),
          "续迁后全部记录应为 v2")
    check(all(v2.read(f"c{i}") == f"s{i}" for i in range(30)), "续迁后全部可读")
    check(key_versions_on_disk(d) == [2], "续迁完成后旧钥应被清理")
    print("ok 进程中断后重启续迁")


def test_two_instances_cooperative_migration():
    v1, d = new_vault()
    v2 = Vault(d)  # 第二个“进程”
    for i in range(40):
        (v1 if i % 2 == 0 else v2).save(f"n{i}", f"val-{i}")
    v1.start_rotation()

    errors = []

    def reader(inst, tag):
        try:
            for _ in range(60):
                i = tag % 40
                check(inst.read(f"n{i}") == f"val-{i}", f"并发读 {i} 正确")
                tag += 1
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    def migrator(inst):
        try:
            for _ in range(120):
                inst.migrate_batch(3)
                inst.maybe_finalize()
                time.sleep(0.005)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=migrator, args=(v1,)),
               threading.Thread(target=migrator, args=(v2,)),
               threading.Thread(target=reader, args=(v1, 0)),
               threading.Thread(target=reader, args=(v2, 13))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check(not errors, f"双实例并发迁移/读写出错：{errors[:3]}")
    check(drain(v1) or v1.status()["rotation"]["status"] == "done",
          "协作迁移应完成")
    check(all(record_version(d, f"n{i}") == 2 for i in range(40)),
          "双实例协作后全部记录应为 v2")
    check(key_versions_on_disk(d) == [2], "旧钥文件应只被清理一次且彻底")
    print("ok 两个实例并发读写 + 协作迁移")


def test_inflight_read_survives_old_key_removal():
    v1, d = new_vault()
    v1.save("svc", "top-secret")
    stale_row = v1._fetch_row("svc")  # 在途请求已取出的旧版本密文行
    check(stale_row[3] == 1, "旧行应为 v1")

    v2 = Vault(d)  # 另一进程完成轮换并清理旧钥文件
    v2.start_rotation()
    drain(v2)
    check(key_versions_on_disk(d) == [2], "旧钥文件已移除")

    # 路径一：本进程缓存里仍有旧钥 → 直接用旧密文解密成功
    check(v1._decrypt_row(stale_row) == "top-secret",
          "在途读（缓存有旧钥）必须能完成")
    # 路径二：缓存也没有旧钥 → 触发“行已迁移”重读后完成
    v1._key_cache.clear()
    check(v1._decrypt_row(stale_row) == "top-secret",
          "在途读（旧钥文件已删）必须重读后完成")
    check(v1.read("svc") == "top-secret", "清理后正常读不受影响")
    print("ok 正在读取旧记录的请求在旧钥移除后仍能完成")


def test_failed_activation_keeps_readable():
    v, d = new_vault()
    v.save("a", "keep-me")
    # 模拟新钥落盘失败
    orig = type(v).__dict__.get("_key_path")
    def boom(version):
        raise OSError("disk full (simulated)")
    v._key_path = boom
    try:
        expect_vault_error(v.start_rotation, 500, "落盘失败应报错")
    finally:
        if orig:
            v._key_path = orig
        else:
            del v._key_path
    check(v.status()["active_version"] == 1, "失败时当前版本不得改变")
    check(v.read("a") == "keep-me", "新钥保存失败时凭据必须保持可读")
    check(v.status()["rotation"] is None, "失败不得留下轮换记录")
    print("ok 新钥保存失败时不启用、凭据保持可读")


def test_supervisor_drives_rotation():
    v, d = new_vault()
    for i in range(25):
        v.save(f"s{i}", f"p{i}")
    sup = MigrationSupervisor(v, batch=4, busy_interval=0.01, idle_interval=0.05)
    sup.start()
    try:
        v.start_rotation()
        deadline = time.time() + 15
        while time.time() < deadline:
            st = v.status()
            if st["rotation"] and st["rotation"]["status"] == "done":
                break
            time.sleep(0.05)
        check(v.status()["rotation"]["status"] == "done",
              "监督线程应自动完成迁移与收尾")
        check(key_versions_on_disk(d) == [2], "监督线程应清理旧钥")
        check(all(v.read(f"s{i}") == f"p{i}" for i in range(25)), "全部可读")
    finally:
        sup.stop()
    print("ok 后台监督线程自动迁移并收尾")


def test_web_api():
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        print("skip web api 测试（缺少 httpx）")
        return
    d = tempfile.mkdtemp(prefix="vault-web-test-")
    os.environ["VAULT_DATA_DIR"] = d
    os.environ["VAULT_USER"] = "ops"
    os.environ["VAULT_PASSWORD"] = "demo1234"
    import importlib
    import app.main as main
    importlib.reload(main)

    # 上下文管理器形式才会执行 lifespan（启动后台迁移监督线程）
    with TestClient(main.app) as client:
        check(client.get("/api/vault/state").status_code == 401, "未登录应 401")
        check(client.post("/api/vault/login", json={
            "username": "ops", "password": "wrong"}).status_code == 403, "错口令应 403")
        r = client.post("/api/vault/login",
                        json={"username": "ops", "password": "demo1234"})
        check(r.status_code == 200, "正确口令应登录成功")

        secret = "web-secret-✓"
        check(client.post("/api/vault/credentials", json={
            "name": "web-conn", "secret": secret}).status_code == 200, "保存应成功")
        r = client.get("/api/vault/credentials/web-conn")
        check(r.json()["secret"] == secret, "读取应还原")
        check(secret.encode() not in db_bytes(d), "经 API 保存的明文不得入库")

        r = client.post("/api/vault/rotate")
        check(r.status_code == 200 and r.json()["to_version"] == 2, "API 轮换应成功")
        check(client.post("/api/vault/rotate").status_code == 409,
              "轮换进行中再次轮换应 409")
        st = {}
        deadline = time.time() + 15
        while time.time() < deadline:
            st = client.get("/api/vault/state").json()
            if st["rotation"] and st["rotation"]["status"] == "done":
                break
            time.sleep(0.1)
        check(st["rotation"]["status"] == "done", "API 触发的轮换应自动完成")
        check(client.get("/api/vault/credentials/web-conn").json()["secret"] == secret,
              "轮换后仍可读")
    print("ok Web API：登录、存取、轮换、进度")


ALL = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    for fn in ALL:
        fn()
    print(f"\n全部 {len(ALL)} 项测试通过")
