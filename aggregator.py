"""
aggregator.py — собирает из списка нормализованных нод все артефакты для репо:
  out/nodes.json          — канонический dump (источник правды, для дедупа между запусками)
  out/sub/combined.txt    — plain-text, одна URI на строку
  out/sub/b64.txt         — base64-подписка (стандарт v2rayN / sing-box import)
  out/nodes/<name>.txt    — файл на каждую ноду (raw URI)
  out/singbox/config.json — готовый sing-box конфиг (best-effort)
  out/clash/config.yaml   — готовый clash конфиг (best-effort)
  out/meta.json           — метаданные: дата, счётчики, предупреждения
"""
import base64
import datetime
import hashlib
import json
import os
import re
from collections import Counter

import nodeparser

MARKER = "out/sub/b64.txt"
_SUPPORTED_SINGBOX = {"ss", "trojan", "vless", "vmess", "hysteria2", "tuic", "wireguard"}
# Сначала типы, у которых клиенты обычно показывают TCP-пинг; Hysteria2/UDP
# ставим после них, чтобы список не начинался экраном из одних n/a.
_PROTOCOL_ORDER = {
    "vless": 0, "trojan": 1, "ss": 2, "vmess": 3,
    "hysteria2": 4, "hy2": 4, "hy": 4,
    "tuic": 5, "wireguard": 6, "ssr": 7,
}

# Переименование: под каким именем узлы выходят в подписку/конфиги.
# {brand} — бренд; {id} — короткий стабильный номер; {proto} — протокол; {country} — страна.
# По умолчанию 'Svaston vpn #а1b2c3' (бренд + уникальный номер, иначе сотни
# серверов с одинаковым именем в клиенте неразличимы). Чистое 'Svaston vpn' —
# задай NODE_NAME_TEMPLATE='{brand}'.
BRAND = os.environ.get("NODE_BRAND", "Svaston vpn")
NAME_TEMPLATE = os.environ.get("NODE_NAME_TEMPLATE", "{brand} #{id}")


def _hash8(n):
    return hashlib.sha1(repr(nodeparser.node_key(n)).encode()).hexdigest()[:8]


def safe_name(n):
    base = n.get("name") or "%s %s:%s" % (n.get("protocol"), n.get("host"), n.get("port"))
    base = re.sub(r"[^\w\-]+", "_", base).strip("_")[:40] or "node"
    return "%s__%s" % (base, _hash8(n))


def brand_name(n):
    return NAME_TEMPLATE.format(brand=BRAND, id=_hash8(n)[:6],
                                proto=n.get("protocol") or "?", country=n.get("country") or "")


def _retitle_node(n):
    nn = dict(n)
    nm = brand_name(n)
    nn["name"] = nm
    nn["raw"] = nodeparser.retitle(n.get("raw", ""), nm)
    return nn


def build(nodes, source="", warnings=None, oldest_id=0, scan_extra=None):
    warnings = list(warnings or [])
    nodes = sorted(
        nodes,
        key=lambda n: (
            _PROTOCOL_ORDER.get((n.get("protocol") or "").lower(), 99),
            (n.get("protocol") or "").lower(),
            str(n.get("host", "")), str(n.get("port", "")), n.get("name", ""),
        ),
    )
    # переименовываем все узлы под бренд (в raw-URI + в полях) до генерации артефактов
    nodes = [_retitle_node(n) for n in nodes]
    files = {}

    files["out/nodes.json"] = json.dumps(nodes, ensure_ascii=False, indent=2)

    lines = [n["raw"] for n in nodes]
    combined = "\n".join(lines) + "\n"
    files["out/sub/combined.txt"] = combined
    files[MARKER] = base64.b64encode(combined.encode()).decode()

    for n in nodes:
        files["out/nodes/%s.txt" % safe_name(n)] = n["raw"] + "\n"

    sb, warn_sb = _build_singbox(nodes)
    warnings += warn_sb
    if sb is not None:
        files["out/singbox/config.json"] = json.dumps(sb, ensure_ascii=False, indent=2)

    cl, warn_cl = _build_clash(nodes)
    warnings += warn_cl
    if cl is not None:
        files["out/clash/config.yaml"] = cl

    meta = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": source,
        "total": len(nodes),
        "protocols": dict(Counter(n.get("protocol", "?") for n in nodes)),
        "scan": {"oldest_id": oldest_id, **(scan_extra or {})},
        "warnings": warnings,
    }
    files["out/meta.json"] = json.dumps(meta, ensure_ascii=False, indent=2)
    return files, meta


# --------------------------------------------------------------- sing-box
def _net_block(node):
    net = node.get("network") or node.get("type") or "tcp"
    if net == "ws":
        return {"type": "ws", "path": node.get("path") or "/",
                "headers": {"Host": node.get("host_header") or node.get("sni") or node.get("host", "")}}
    if net in ("grpc", "gun"):
        return {"type": "grpc", "service_name": node.get("service_name") or node.get("path", "")}
    if net in ("http", "h2"):
        return {"type": "http", "path": node.get("path") or "/"}
    if net in ("kcp", "mkcp"):
        return {"type": "kcp"}
    if net == "quic":
        return {"type": "quic"}
    return {}


def _tls_block(node, host):
    sec = node.get("security")
    if sec == "reality":
        return {"reality": {"server_name": node.get("sni") or host, "public_key": node.get("pbk", ""),
                            "fingerprint": node.get("fingerprint") or "chrome"}}
    if sec == "tls":
        return {"tls": {"server_name": node.get("sni") or host, "insecure": bool(node.get("allow_insecure"))}}
    return {}


def _sb_server(node, name):
    host = node.get("host")
    port = int(node.get("port") or 0)
    p = node.get("protocol")
    if p == "ss":
        if not host or not port:
            raise ValueError("no host/port")
        ob = {"type": "shadowsocks", "tag": name, "server": host, "server_port": port,
              "method": node.get("method") or "aes-256-gcm", "password": node.get("password", "")}
        nb = _net_block(node)
        if nb:
            ob.update(nb)
        return ob
    if p == "trojan":
        if not host or not port:
            raise ValueError("no host/port")
        ob = {"type": "trojan", "tag": name, "server": host, "server_port": port, "password": node.get("password", "")}
        ob.update(_net_block(node))
        ob.update(_tls_block(node, host))
        return ob
    if p == "vless":
        if not host or not port or not node.get("uuid"):
            raise ValueError("no host/port/uuid")
        ob = {"type": "vless", "tag": name, "server": host, "server_port": port, "uuid": node.get("uuid", "")}
        if node.get("flow"):
            ob["flow"] = node["flow"]
        ob["encryption"] = node.get("encryption") or "none"
        ob.update(_net_block(node))
        ob.update(_tls_block(node, host))
        return ob
    if p == "vmess":
        if not host or not port or not node.get("uuid"):
            raise ValueError("no host/port/uuid")
        ob = {"type": "vmess", "tag": name, "server": host, "server_port": port, "uuid": node.get("uuid", ""),
              "alter_id": int(node.get("aid") or 0), "cipher": node.get("cipher") or "auto"}
        ob.update(_net_block(node))
        t = _tls_block(node, host)
        if node.get("tls") and not t:
            t = {"tls": {"server_name": node.get("sni") or host, "insecure": False}}
        ob.update(t)
        return ob
    if p == "hysteria2":
        if not host or not port:
            raise ValueError("no host/port")
        ob = {"type": "hysteria2", "tag": name, "server": host, "server_port": port, "password": node.get("password", "")}
        ob["tls"] = {"server_name": node.get("sni") or host, "insecure": bool(node.get("insecure"))}
        return ob
    if p == "tuic":
        if not host or not port or not node.get("uuid"):
            raise ValueError("no host/port/uuid")
        ob = {"type": "tuic", "tag": name, "server": host, "server_port": port, "uuid": node.get("uuid", ""),
              "congestion_control": node.get("congestion") or "bbr"}
        ob["tls"] = {"server_name": node.get("sni") or host, "insecure": bool(node.get("allow_insecure", True))}
        return ob
    if p == "wireguard":
        ep = node.get("endpoint") or node.get("host")
        pk = node.get("private_key")
        if not ep or not pk:
            raise ValueError("no endpoint/private_key")
        ob = {"type": "wireguard", "tag": name, "server": ep, "server_port": int(node.get("port") or 443), "private_key": pk}
        if node.get("public_key"):
            ob["peer_public_key"] = node["public_key"]
        if node.get("ip"):
            ob["local_address"] = [node["ip"]]
        else:
            ob["local_address"] = ["10.0.0.2/32"]
        ob["mtu"] = int(node.get("mtu") or 1420)
        return ob
    raise ValueError("unsupported %s" % p)


def _build_singbox(nodes):
    outbounds = []
    warnings = []
    seen_tags = set()
    for n in nodes:
        name = safe_name(n)
        if name in seen_tags:
            continue
        seen_tags.add(name)
        if n.get("protocol") not in _SUPPORTED_SINGBOX:
            warnings.append("singbox: skip %s (%s)" % (name, n.get("protocol")))
            continue
        try:
            ob = _sb_server(n, name)
            outbounds.append(ob)
        except Exception as e:  # noqa: BLE001
            warnings.append("singbox: skip %s: %s" % (name, e))
    if not outbounds:
        return None, warnings
    config = {
        "log": {"level": "warn"},
        "dns": {"servers": [{"tag": "google", "address": "tls://8.8.8.8"},
                            {"tag": "local", "address": "223.5.5.5", "detour": "direct"}]},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 10808}],
        "outbounds": [
            *outbounds,
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"},
        ],
        "route": {"final": "direct", "auto_detect_interface": True,
                  "rules": [{"outbound": "dns-out", "protocol": "dns"}]},
    }
    return config, warnings


# ------------------------------------------------------------------ clash
def _build_clash(nodes):
    try:
        import yaml
    except Exception:
        return None, ["clash: PyYAML not installed, skipped"]
    proxies = []
    warnings = []
    for n in nodes:
        name = safe_name(n)
        host = n.get("host")
        port = int(n.get("port") or 0)
        p = n.get("protocol")
        d = None
        try:
            base = {"name": name, "server": host, "port": port}
            if p == "ss":
                d = {**base, "type": "ss", "cipher": n.get("method") or "aes-256-gcm", "password": n.get("password", "")}
            elif p == "ssr":
                d = {**base, "type": "ssr", "cipher": n.get("method", ""), "password": n.get("password", ""),
                     "protocol": n.get("plugin", "origin"), "protocol-param": "",
                     "obfs": n.get("obfs", "none"), "obfs-param": ""}
            elif p == "trojan":
                d = {**base, "type": "trojan", "password": n.get("password", ""), "udp": True}
            elif p == "vless":
                d = {**base, "type": "vless", "uuid": n.get("uuid", ""), "udp": True,
                     "flow": n.get("flow", "") or ""}
                if n.get("network") not in (None, "", "tcp"):
                    d["network"] = n.get("network")
            elif p == "vmess":
                d = {**base, "type": "vmess", "uuid": n.get("uuid", ""), "alterId": int(n.get("aid") or 0),
                     "cipher": n.get("cipher") or "auto", "udp": True}
                if n.get("network") not in (None, "", "tcp"):
                    d["network"] = n.get("network")
            elif p == "hysteria2":
                d = {**base, "type": "hysteria2", "password": n.get("password", ""),
                     "server-name": n.get("sni") or host, "skip-cert-verify": bool(n.get("insecure"))}
            elif p == "tuic":
                d = {**base, "type": "tuic", "uuid": n.get("uuid", ""),
                     "congestion-controller": n.get("congestion") or "bbr", "udp": True,
                     "server-name": n.get("sni") or host, "skip-cert-verify": bool(n.get("allow_insecure", True))}
            else:
                raise ValueError(p)
            if d and not (d.get("server") and d.get("port")):
                raise ValueError("no server/port")
            if p in ("trojan", "vless", "vmess"):
                if n.get("security") in ("tls", "reality") or n.get("tls"):
                    d["tls"] = True
                    d["server-name"] = n.get("sni") or host
                    d["skip-cert-verify"] = bool(n.get("allow_insecure"))
                if n.get("pbk"):
                    d["reality-opts"] = {"public-key": n.get("pbk")}
                if n.get("network") == "ws":
                    d["ws-opts"] = {"path": n.get("path") or "/",
                                    "headers": {"Host": n.get("host_header") or host}}
                if n.get("network") == "grpc":
                    d["grpc-opts"] = {"grpc-service-name": n.get("service_name") or n.get("path", "")}
            if p == "ss" and n.get("network") not in (None, "", "tcp"):
                d["plugin"] = "obfs"
            if d:
                proxies.append(d)
        except Exception as e:  # noqa: BLE001
            warnings.append("clash: skip %s: %s" % (name, e))
    if not proxies:
        return None, warnings
    names = [p["name"] for p in proxies]
    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "dns": {"enable": True, "enhanced-mode": "fake-ip", "nameserver": ["8.8.8.8", "1.1.1.1"]},
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO"] + names + ["DIRECT"]},
            {"name": "AUTO", "type": "url-test", "proxies": names,
             "url": "http://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50},
        ],
        "rules": ["MATCH,PROXY"],
    }
    return yaml.safe_dump(config, allow_unicode=True, sort_keys=False, width=10000), warnings
