"""正确性测试：

1. 穷举交叉验证：在一个小的 (IP, IP, 端口, 协议) 空间内，对随机生成的新旧规则集，
   用暴力枚举每个点的首条匹配结果作为基准，核对 analyze() 的逐条判定
   （是否放开、witness 是否合法、旧侧命中是否一致）。
   这验证了“覆盖整个地址与端口空间、不抽样”的判定与暴力枚举完全等价，
   包括多条规则联合覆盖与顺序变化的情形。
2. 内置变更示例的预期结果。
3. 输入校验：非法输入必须定位到规则且不进入计算。

运行：python3 tests/test_exactness.py
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.example import NEW_EXAMPLE, OLD_EXAMPLE
from app.firewall import (ValidationError, analyze, validate_rulesets)
from app.firewall import Rule

MAX_IP = 7      # 测试用 3 位“地址”空间：0..7
MAX_PORT = 5    # 测试用端口空间：0..5


def rand_rect(rng):
    def iv(hi):
        a, b = rng.randint(0, hi), rng.randint(0, hi)
        return (min(a, b), max(a, b))
    return (iv(MAX_IP), iv(MAX_IP), iv(MAX_PORT))


def rand_rules(rng, n):
    return [Rule(index=i,
                 proto=rng.choice(["tcp", "udp"]),
                 action=rng.choice(["allow", "allow", "deny"]),
                 rect=rand_rect(rng))
            for i in range(n)]


def eval_policy(rules, proto, pt):
    """暴力首条匹配：返回命中的规则或 None（默认拒绝）。"""
    s, d, p = pt
    for r in rules:
        if r.proto != proto:
            continue
        (slo, shi), (dlo, dhi), (plo, phi) = r.rect
        if slo <= s <= shi and dlo <= d <= dhi and plo <= p <= phi:
            return r
    return None


def brute_opened(old, new):
    """暴力枚举全空间：{新规则 index: 该规则实际放行且旧规则拒绝的点集}。"""
    opened = {r.index: set() for r in new if r.action == "allow"}
    for proto in ("tcp", "udp"):
        for s in range(MAX_IP + 1):
            for d in range(MAX_IP + 1):
                for p in range(MAX_PORT + 1):
                    pt = (s, d, p)
                    nm = eval_policy(new, proto, pt)
                    om = eval_policy(old, proto, pt)
                    if nm is not None and nm.action == "allow" and \
                       not (om is not None and om.action == "allow"):
                        opened[nm.index].add((proto,) + pt)
    return opened


def test_bruteforce_crosscheck(trials=3000, seed=20261111):
    rng = random.Random(seed)
    checked = opened_cases = 0
    for t in range(trials):
        old = rand_rules(rng, rng.randint(0, 8))
        new = rand_rules(rng, rng.randint(0, 8))
        expected = brute_opened(old, new)
        findings = {f.rule.index: f for f in analyze(old, new)}

        # analyze 必须恰好覆盖新规则集中的所有 allow 规则
        assert set(findings) == set(expected), \
            f"trial {t}: findings 与 allow 规则集合不一致"

        for idx, f in findings.items():
            pts = expected[idx]
            assert f.opened == bool(pts), \
                f"trial {t} rule {idx}: opened={f.opened} 但暴力结果点数={len(pts)}"
            checked += 1
            if f.opened:
                opened_cases += 1
                s, d, proto, p = f.witness
                # witness 必须是该规则实际放行且旧规则拒绝的真实点
                assert (proto, s, d, p) in pts, \
                    f"trial {t} rule {idx}: witness 不在暴力点集内"
                # 旧侧命中必须与暴力首条匹配一致
                om = eval_policy(old, proto, (s, d, p))
                if om is None:
                    assert f.old_match is None, \
                        f"trial {t} rule {idx}: 旧侧应为默认拒绝"
                else:
                    assert om.action == "deny"
                    assert f.old_match is not None and f.old_match.index == om.index, \
                        f"trial {t} rule {idx}: 旧侧命中规则不一致"
    print(f"[1] 穷举交叉验证通过：{trials} 组随机规则集，"
          f"共核对 {checked} 条 allow 规则（其中 {opened_cases} 条存在新增放行）")


def test_builtin_example():
    old_rules, new_rules = validate_rulesets(OLD_EXAMPLE, NEW_EXAMPLE)
    findings = {f.rule.index + 1: f for f in analyze(old_rules, new_rules)}

    # #1 SSH 未变；#3 分支 /23 被旧 #4+#5 联合覆盖；#5 DNS 仅顺序变化
    assert not findings[1].opened
    assert not findings[3].opened
    assert not findings[5].opened

    # #2 Web 80-443：放开 81-442，witness 端口 81，旧侧默认拒绝
    f2 = findings[2]
    assert f2.opened
    s, d, proto, p = f2.witness
    assert proto == "tcp" and p == 81 and d == int(__import__("ipaddress").IPv4Address("10.0.0.10"))
    assert f2.old_match is None

    # #4 MySQL：旧侧命中显式 deny（旧规则 #6）
    f4 = findings[4]
    assert f4.opened
    assert f4.old_match is not None and f4.old_match.index + 1 == 6
    assert f4.old_match.action == "deny"
    print("[2] 内置示例判定符合预期：#2 放开 81-442（旧侧默认拒绝），"
          "#4 放开 MySQL（旧侧命中显式 deny #6），#1/#3/#5 无新增放行")


def test_validation():
    # 合法输入
    validate_rulesets([], [])
    validate_rulesets([{"src": "1.2.3.4", "dst": "0.0.0.0/0", "proto": "TCP",
                        "ports": 80, "action": "Allow"}], [])

    def expect_error(old, new, side, rule, needle):
        try:
            validate_rulesets(old, new)
        except ValidationError as e:
            hit = [x for x in e.errors
                   if x["side"] == side and x["rule"] == rule and needle in x["message"]]
            assert hit, f"未找到预期错误 {side}/{rule}/{needle}: {e.errors}"
            return
        raise AssertionError(f"应报校验错误：{needle}")

    good = {"src": "0.0.0.0/0", "dst": "10.0.0.0/8", "proto": "tcp",
            "ports": [80, 443], "action": "allow"}
    expect_error([], [dict(good, ports=[443, 80])], "new", 2 - 1, "下界大于上界")
    expect_error([], [dict(good, ports=[0, 65536])], "new", 1, "0~65535")
    expect_error([], [dict(good, ports="80-443")], "new", 1, "ports")
    expect_error([], [dict(good, proto="icmp")], "new", 1, "proto")
    expect_error([], [dict(good, action="permit")], "new", 1, "action")
    expect_error([], [dict(good, src="10.0.0.0/33")], "new", 1, "CIDR")
    expect_error([], [dict(good, dst="999.1.1.1/32")], "new", 1, "CIDR")
    expect_error([], [dict(good, port=80)], "new", 1, "无法识别的字段")
    expect_error([], [{"dst": "10.0.0.0/8", "proto": "tcp", "ports": 80,
                       "action": "allow"}], "new", 1, "缺少字段 src")
    expect_error([dict(good, comment=123)], [], "old", 1, "comment")
    expect_error([], ["not-a-rule"], "new", 1, "JSON 对象")
    expect_error([], [dict(good, ports=[80, 80], extra=1)], "new", 1, "无法识别")
    # 错误定位到具体序号：第 3 条坏
    expect_error([], [good, good, dict(good, proto="gre")], "new", 3, "proto")
    # 超过 30 条
    try:
        validate_rulesets([], [dict(good) for _ in range(31)])
        raise AssertionError("应报超上限")
    except ValidationError as e:
        assert any("30" in x["message"] for x in e.errors)
    print("[3] 输入校验符合预期：非法输入逐条定位（侧/规则号/原因），超上限拒绝")


if __name__ == "__main__":
    test_bruteforce_crosscheck()
    test_builtin_example()
    test_validation()
    print("全部测试通过。")
