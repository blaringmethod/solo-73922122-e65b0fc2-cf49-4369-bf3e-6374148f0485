"""一键载入的变更示例。

场景：一次典型的防火墙变更——
  * Web 端口由 80、443 两条合并为一条 80-443（误把区间写宽，放开了 81-442）；
  * 两个 /24 分支网段合并为 /23 超网（被旧规则联合覆盖，无新增放行）；
  * 新增办公网访问 MySQL（旧规则中被显式 deny 拦截）；
  * DNS 与数据库段 deny 的顺序对调（协议/网段不相交，无实际影响）。
"""

OLD_EXAMPLE = [
    {"comment": "管理网段 SSH",
     "src": "192.168.1.0/24", "dst": "10.0.0.0/24",
     "proto": "tcp", "ports": [22, 22], "action": "allow"},
    {"comment": "Web HTTP",
     "src": "0.0.0.0/0", "dst": "10.0.0.10/32",
     "proto": "tcp", "ports": 80, "action": "allow"},
    {"comment": "Web HTTPS",
     "src": "0.0.0.0/0", "dst": "10.0.0.10/32",
     "proto": "tcp", "ports": 443, "action": "allow"},
    {"comment": "分支机构A 访问报表系统",
     "src": "172.16.0.0/24", "dst": "10.0.0.20/32",
     "proto": "tcp", "ports": 8080, "action": "allow"},
    {"comment": "分支机构B 访问报表系统",
     "src": "172.16.1.0/24", "dst": "10.0.0.20/32",
     "proto": "tcp", "ports": 8080, "action": "allow"},
    {"comment": "阻断一切访问数据库段",
     "src": "0.0.0.0/0", "dst": "10.0.0.32/27",
     "proto": "tcp", "ports": [0, 65535], "action": "deny"},
    {"comment": "DNS 服务器",
     "src": "0.0.0.0/0", "dst": "10.0.0.53/32",
     "proto": "udp", "ports": 53, "action": "allow"},
]

NEW_EXAMPLE = [
    {"comment": "管理网段 SSH（未变）",
     "src": "192.168.1.0/24", "dst": "10.0.0.0/24",
     "proto": "tcp", "ports": [22, 22], "action": "allow"},
    {"comment": "Web 端口合并（本想只开 80 和 443）",
     "src": "0.0.0.0/0", "dst": "10.0.0.10/32",
     "proto": "tcp", "ports": [80, 443], "action": "allow"},
    {"comment": "两个分支合并为超网 172.16.0.0/23",
     "src": "172.16.0.0/23", "dst": "10.0.0.20/32",
     "proto": "tcp", "ports": 8080, "action": "allow"},
    {"comment": "新增：办公网临时访问 MySQL",
     "src": "192.168.2.0/24", "dst": "10.0.0.40/32",
     "proto": "tcp", "ports": 3306, "action": "allow"},
    {"comment": "DNS 服务器（顺序前移，无实际影响）",
     "src": "0.0.0.0/0", "dst": "10.0.0.53/32",
     "proto": "udp", "ports": 53, "action": "allow"},
    {"comment": "阻断一切访问数据库段（顺序后移）",
     "src": "0.0.0.0/0", "dst": "10.0.0.32/27",
     "proto": "tcp", "ports": [0, 65535], "action": "deny"},
]
