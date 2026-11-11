"""防火墙规则差集精确计算核心。

语义约定：
  - 规则按顺序匹配，首条命中生效；
  - 未命中任何规则的流量一律默认拒绝（default deny）。

每条规则是 (源IPv4, 目的IPv4, 目的端口) 空间中的一个长方体（协议维度单独处理，
TCP 与 UDP 互不相关）。本模块用长方体差集在整个地址/端口空间上精确求解，
不使用任何抽样：对“新规则”中的每一条 allow，判断其实际生效区域中是否存在
被“旧规则”（含默认拒绝）拒绝的流量；若存在，给出一个具体的 witness 五元组，
以及该流量在新旧两侧各自命中的规则。
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

MAX_RULES = 30          # 每侧规则数上限
MIN_PORT = 0
MAX_PORT = 65535

# 计算预算（长方体拆分次数上限）。正常的 30+30 条规则远低于此值，
# 预算仅用于防御极端构造的输入导致计算时间过长。
_SUBTRACT_BUDGET = 5_000_000

PROTOCOLS = ("tcp", "udp")
ACTIONS = ("allow", "deny")


class ComplexityError(Exception):
    """规则组合过于复杂，超出计算预算。"""


class ValidationError(Exception):
    """输入校验失败。errors 为 [{side, rule, message}, ...]。"""

    def __init__(self, errors):
        super().__init__("validation failed")
        self.errors = errors


# ---------------------------------------------------------------------------
# 长方体运算
# 长方体 = ((lo, hi), (lo, hi), (lo, hi))，三个维度依次为 源IP、目的IP、端口，
# 均为闭区间整数。所有运算在整个空间上精确进行，不抽样。
# ---------------------------------------------------------------------------

def _intersect(a, b):
    """两个长方体的交集；不相交返回 None。"""
    out = []
    for d in range(3):
        lo = a[d][0] if a[d][0] > b[d][0] else b[d][0]
        hi = a[d][1] if a[d][1] < b[d][1] else b[d][1]
        if lo > hi:
            return None
        out.append((lo, hi))
    return tuple(out)


def _subtract(a, b):
    """返回 a \\ b 的不相交长方体列表（0~6 个）。"""
    inter = _intersect(a, b)
    if inter is None:
        return [a]
    pieces = []
    rest = a
    for d in range(3):
        lo, hi = rest[d]
        ilo, ihi = inter[d]
        if lo < ilo:
            pieces.append(rest[:d] + ((lo, ilo - 1),) + rest[d + 1:])
        if ihi < hi:
            pieces.append(rest[:d] + ((ihi + 1, hi),) + rest[d + 1:])
        rest = rest[:d] + (inter[d],) + rest[d + 1:]
    return pieces


def _subtract_many(pieces, blockers, budget):
    """从一组不相交长方体中减去所有 blocker，返回剩余的不相交长方体列表。"""
    for b in blockers:
        if not pieces:
            break
        nxt = []
        for p in pieces:
            nxt.extend(_subtract(p, b))
        budget[0] -= len(pieces)
        if budget[0] <= 0:
            raise ComplexityError(
                "规则组合过于复杂，超出计算预算，请简化规则后重试")
        pieces = nxt
    return pieces


def _contains(rect, point):
    (slo, shi), (dlo, dhi), (plo, phi) = rect
    s, d, p = point
    return slo <= s <= shi and dlo <= d <= dhi and plo <= p <= phi


# ---------------------------------------------------------------------------
# 规则数据结构与文本展示
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    index: int                 # 在所属规则集中的位置（0 起）
    proto: str                 # 'tcp' | 'udp'
    action: str                # 'allow' | 'deny'
    rect: tuple                # ((src_lo, src_hi), (dst_lo, dst_hi), (port_lo, port_hi))
    src_cidr: str = ""         # 规范化后的 CIDR 文本（仅用于展示）
    dst_cidr: str = ""
    port_lo: int = 0
    port_hi: int = 0
    comment: str | None = None

    def text(self) -> str:
        if self.port_lo == self.port_hi:
            port = str(self.port_lo)
        else:
            port = f"{self.port_lo}-{self.port_hi}"
        return (f"{self.action} {self.proto} {self.src_cidr} → "
                f"{self.dst_cidr} 端口 {port}")


@dataclass
class Finding:
    """对一条新 allow 规则的判定结果。"""
    rule: Rule
    opened: bool                       # 是否放行了旧规则拒绝的流量
    witness: tuple | None = None       # (src_int, dst_int, proto, port_int)
    old_match: Rule | None = None      # 旧规则集中命中的 deny 规则；None 表示默认拒绝


# ---------------------------------------------------------------------------
# 输入校验：任何非法输入都定位到具体规则，且不进入计算
# ---------------------------------------------------------------------------

_ALLOWED_KEYS = {"src", "dst", "proto", "ports", "action", "comment"}


def _parse_cidr(value):
    """解析 IPv4 CIDR（宽容处理主机位，如 10.0.0.1/24 归一化为 10.0.0.0/24）。

    裸 IP（如 1.2.3.4）按 /32 处理。非法输入返回 None。
    """
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.IPv4Network(value.strip(), strict=False)
    except ValueError:
        return None


def validate_rulesets(old_data, new_data):
    """校验两侧规则集。全部合法时返回 (old_rules, new_rules)，
    否则抛出 ValidationError（携带全部错误，逐条定位）。"""
    errors = []
    old_rules = _validate_one(old_data, "old", "旧规则", errors)
    new_rules = _validate_one(new_data, "new", "新规则", errors)
    if errors:
        raise ValidationError(errors)
    return old_rules, new_rules


def _validate_one(data, side, label, errors):
    if not isinstance(data, list):
        errors.append({"side": side, "rule": None,
                       "message": f"{label}必须是 JSON 数组（[...]）"})
        return []
    if len(data) > MAX_RULES:
        errors.append({"side": side, "rule": None,
                       "message": f"{label}共 {len(data)} 条，超过 {MAX_RULES} 条上限"})
        return []
    rules = []
    for i, item in enumerate(data):
        r = _validate_rule(item, i, side, errors)
        if r is not None:
            rules.append(r)
    return rules


def _validate_rule(item, idx, side, errors):
    no = idx + 1

    def err(msg):
        errors.append({"side": side, "rule": no, "message": msg})

    if not isinstance(item, dict):
        err(f"必须是 JSON 对象，实际为 {type(item).__name__}")
        return None

    unknown = sorted(set(item) - _ALLOWED_KEYS)
    if unknown:
        err("存在无法识别的字段：" + ", ".join(unknown)
            + "（允许的字段：action, comment, dst, ports, proto, src）")
        return None

    ok = True

    src_net = dst_net = None
    for key, name in (("src", "源地址"), ("dst", "目的地址")):
        if key not in item or item[key] is None:
            err(f"缺少字段 {key}（{name}，IPv4 CIDR，如 \"10.0.0.0/8\"）")
            ok = False
            continue
        net = _parse_cidr(item[key])
        if net is None:
            err(f"字段 {key} 不是合法的 IPv4 CIDR：{item[key]!r}")
            ok = False
        elif key == "src":
            src_net = net
        else:
            dst_net = net

    port_lo = port_hi = None
    if "ports" not in item or item["ports"] is None:
        err("缺少字段 ports（目的端口闭区间 [下界, 上界]，单端口可写 [80, 80] 或 80）")
        ok = False
    else:
        p = item["ports"]
        pair = None
        if isinstance(p, int) and not isinstance(p, bool):
            pair = (p, p)
        elif (isinstance(p, list) and len(p) == 2
              and all(isinstance(x, int) and not isinstance(x, bool) for x in p)):
            pair = (p[0], p[1])
        else:
            err("字段 ports 必须是 [下界, 上界] 形式的二元整数数组（或单个整数端口）")
            ok = False
        if pair is not None:
            lo, hi = pair
            if not (MIN_PORT <= lo <= MAX_PORT and MIN_PORT <= hi <= MAX_PORT):
                err(f"端口必须在 {MIN_PORT}~{MAX_PORT} 之间：[{lo}, {hi}]")
                ok = False
            elif lo > hi:
                err(f"端口区间下界大于上界：[{lo}, {hi}]")
                ok = False
            else:
                port_lo, port_hi = lo, hi

    proto = item.get("proto")
    if not isinstance(proto, str) or proto.strip().lower() not in PROTOCOLS:
        err('字段 proto 必须是 "tcp" 或 "udp"')
        ok = False
    else:
        proto = proto.strip().lower()

    action = item.get("action")
    if not isinstance(action, str) or action.strip().lower() not in ACTIONS:
        err('字段 action 必须是 "allow" 或 "deny"')
        ok = False
    else:
        action = action.strip().lower()

    comment = item.get("comment")
    if comment is not None and not isinstance(comment, str):
        err("字段 comment 必须是字符串")
        ok = False

    if not ok:
        return None

    return Rule(
        index=idx,
        proto=proto,
        action=action,
        rect=((int(src_net.network_address), int(src_net.broadcast_address)),
              (int(dst_net.network_address), int(dst_net.broadcast_address)),
              (port_lo, port_hi)),
        src_cidr=str(src_net),
        dst_cidr=str(dst_net),
        port_lo=port_lo,
        port_hi=port_hi,
        comment=comment,
    )


# ---------------------------------------------------------------------------
# 核心判定
# ---------------------------------------------------------------------------

def _allow_region(rules, proto, budget):
    """规则集中被 allow 实际放行的区域（不相交长方体列表）。

    按顺序处理：每条规则的“生效区域”是其矩形减去之前所有规则已覆盖的部分；
    allow 规则的生效区域并入放行集。deny 规则只起遮蔽作用。
    """
    decided = []
    allow_pieces = []
    for r in rules:
        if r.proto != proto:
            continue
        if r.action == "allow":
            allow_pieces.extend(_subtract_many([r.rect], decided, budget))
        decided.append(r.rect)
    return allow_pieces


def _first_match(rules, proto, point):
    """返回首个命中该点的规则；无命中返回 None（默认拒绝）。"""
    for r in rules:
        if r.proto != proto:
            continue
        if _contains(r.rect, point):
            return r
    return None


def analyze(old_rules, new_rules):
    """逐条检查新规则中的 allow 是否放行了旧规则（含默认拒绝）拒绝的流量。

    返回 list[Finding]，按新规则顺序排列（仅含 allow 规则）。
    整个过程是长方体精确差集运算，覆盖全部地址与端口空间，不抽样。
    """
    budget = [_SUBTRACT_BUDGET]
    findings = []
    for proto in PROTOCOLS:
        old_allow = _allow_region(old_rules, proto, budget)
        earlier = []  # 新规则集中位于当前规则之前的所有矩形（同协议）
        for r in new_rules:
            if r.proto != proto:
                continue
            if r.action == "allow":
                # 该 allow 实际放行且旧规则拒绝的区域
                # = 矩形 − 之前的新规则 − 旧规则放行区域
                remaining = _subtract_many([r.rect], earlier + old_allow, budget)
                if remaining:
                    w = remaining[0]
                    point = (w[0][0], w[1][0], w[2][0])
                    old_hit = _first_match(old_rules, proto, point)
                    # 该点不在旧放行区域内，故旧侧命中必为 deny 或默认拒绝
                    assert old_hit is None or old_hit.action == "deny"
                    findings.append(Finding(
                        rule=r, opened=True,
                        witness=(point[0], point[1], proto, point[2]),
                        old_match=old_hit))
                else:
                    findings.append(Finding(rule=r, opened=False))
            earlier.append(r.rect)
    findings.sort(key=lambda f: f.rule.index)
    return findings
