"""
liveness.py — выборочная проверка РАБОТЫ прокси перед публикацией.

Не считаем открытый TCP-порт доказательством рабочего VPN: для VLESS/VMess/
Trojan/Shadowsocks запускается Xray и делается HTTPS-запрос ЧЕРЕЗ локальный
SOCKS-туннель. Hysteria2 проверяется официальным клиентом. Считаем ноду
подтверждённо рабочей только если тестовый URL вернул HTTP 200/204.

Проверяется выборка, приоритет — кандидаты с предыдущей неудачей, затем
ротация. Подтверждённый dead фиксируется после двух последовательных провалов.
Список для подписки main.py собирает только из нод, прошедших реальный тест.

Переменные: LIVENESS_TIMEOUT, LIVENESS_WORKERS, LIVENESS_MAX, LIVENESS_DEAD,
LIVENESS_ROTATE, HYSTERIA_BIN, XRAY_BIN.
"""
import hashlib
import json
import os
import select
import shutil
import socket
import subprocess
import tempfile
import time

TIMEOUT = float(os.environ.get("LIVENESS_TIMEOUT", "8"))
WORKERS = int(os.environ.get("LIVENESS_WORKERS", "20"))
MAX_CHECKS = int(os.environ.get("LIVENESS_MAX", "60"))
DEAD_THRESHOLD = int(os.environ.get("LIVENESS_DEAD", "2"))
ROTATE_PERIOD = int(os.environ.get("LIVENESS_ROTATE", "300"))
HY2_TIMEOUT = float(os.environ.get("HY2_CHECK_TIMEOUT", "10"))
HYSTERIA_BIN = os.environ.get("HYSTERIA_BIN") or shutil.which("hysteria") or ""
XRAY_BIN = os.environ.get("XRAY_BIN") or shutil.which("xray") or ""

_XRAY_PROTOS = {"vless", "vmess", "trojan", "ss"}
_HY2_PROTOS = {"hysteria2", "hy2", "hy"}
_UDP_PROTOS = {"hysteria2", "hy2", "hy", "tuic", "wireguard"}
_TEST_URLS = (
    "https://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
)


def _key(n):
    import nodeparser
    return repr(nodeparser.node_key(n))


def _proto(n):
    return (n.get("protocol") or "").lower()


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_local_socks(proc, port, timeout=2.0):
    deadline = time.monotonic() + max(0.2, timeout)
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _https_via_socks(port, timeout=4.0):
    """Проверяет именно трафик через прокси, а не только локальный handshake."""
    total = max(3, int(timeout))
    for url in _TEST_URLS:
        try:
            r = subprocess.run(
                ["curl", "-sS", "-o", os.devnull, "-w", "%{http_code}",
                 "--connect-timeout", str(min(3, total)), "--max-time", str(total),
                 "--socks5-hostname", "127.0.0.1:%d" % int(port), url],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, timeout=total + 1,
            )
            if r.returncode == 0 and r.stdout.strip() in ("200", "204"):
                return True
        except (OSError, subprocess.TimeoutExpired):
            continue
    return False


def _write_private_config(text, suffix):
    fd, path = tempfile.mkstemp(prefix="vpn-probe-", suffix=suffix)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def _run_proxy_test(command, config_text, port, timeout):
    """Starts a local client, checks an HTTPS request through its SOCKS port."""
    path = None
    proc = None
    try:
        path = _write_private_config(config_text, ".json" if "xray" in command[0].lower() else ".yaml")
        if "xray" in command[0].lower():
            # Xray accepts JSON via -c; Hysteria uses -c as well.
            full_command = command + [path]
        else:
            full_command = command + ["-c", path, "--disable-update-check", "-l", "error"]
        proc = subprocess.Popen(
            full_command, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if not _wait_local_socks(proc, port, timeout=min(3.0, timeout)):
            return False
        return _https_via_socks(port, timeout=max(3.0, timeout))
    except (FileNotFoundError, PermissionError, OSError, ValueError):
        # Ошибка бинарника/среды — unknown, не ложно записываем узел как dead.
        return None
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=1)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=1)
                except Exception:
                    pass
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def _xray_stream(n):
    """Converts the parsed share-link fields to Xray streamSettings."""
    network = (n.get("network") or n.get("type") or "tcp").lower()
    if network == "gun":
        network = "grpc"
    if network == "raw":
        network = "tcp"
    allowed = {"tcp", "ws", "grpc", "xhttp", "httpupgrade", "http", "h2"}
    if network not in allowed:
        return None
    stream = {"network": network}
    security = (n.get("security") or "").lower()
    if not security and _proto(n) == "trojan":
        security = "tls"
    if not security and _proto(n) == "vmess" and n.get("tls"):
        security = "tls"
    if security in ("", "none"):
        security = "none"
    if security not in ("none", "tls", "reality"):
        return None
    stream["security"] = security

    if security == "reality":
        if not n.get("pbk"):
            return None
        stream["realitySettings"] = {
            "show": False,
            "fingerprint": n.get("fingerprint") or "chrome",
            "serverName": n.get("sni") or n.get("host"),
            "publicKey": n.get("pbk"),
            "shortId": n.get("sid") or "",
            "spiderX": n.get("spx") or "",
        }
    elif security == "tls":
        tls = {
            "serverName": n.get("sni") or n.get("host"),
            "allowInsecure": bool(n.get("allow_insecure")),
        }
        alpn = n.get("alpn") or ""
        if isinstance(alpn, str) and alpn.strip():
            tls["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        elif isinstance(alpn, list) and alpn:
            tls["alpn"] = alpn
        elif network == "xhttp":
            # XHTTP over TLS needs HTTP/2; some shared links omit this query key.
            tls["alpn"] = ["h2"]
        if n.get("fingerprint"):
            tls["fingerprint"] = n["fingerprint"]
        stream["tlsSettings"] = tls

    path = n.get("path") or "/"
    host = n.get("host_header") or n.get("sni") or n.get("host") or ""
    if network == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host}}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": n.get("service_name") or path}
    elif network == "xhttp":
        xhttp = {"path": path, "mode": n.get("mode") or "auto"}
        if host:
            xhttp["host"] = host
        extra = n.get("xhttp_extra") or ""
        if extra:
            try:
                xhttp["extra"] = json.loads(extra)
            except (TypeError, ValueError):
                return None
        stream["xhttpSettings"] = xhttp
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path, "host": host}
    elif network in ("http", "h2"):
        stream["httpSettings"] = {"path": path, "host": [host] if host else []}
    return stream


def _xray_config(n, local_port):
    p = _proto(n)
    host = (n.get("host") or "").strip()
    try:
        port = int(n.get("port") or 0)
    except Exception:
        port = 0
    if p not in _XRAY_PROTOS or not host or port < 1:
        return None

    outbound = {"tag": "probe", "protocol": p}
    if p == "vless":
        user = {"id": n.get("uuid") or "", "encryption": n.get("encryption") or "none"}
        if not user["id"]:
            return None
        if n.get("flow"):
            user["flow"] = n["flow"]
        outbound["settings"] = {"vnext": [{"address": host, "port": port, "users": [user]}]}
    elif p == "vmess":
        user = {"id": n.get("uuid") or "", "alterId": int(n.get("aid") or 0),
                "security": n.get("cipher") or "auto"}
        if not user["id"]:
            return None
        outbound["settings"] = {"vnext": [{"address": host, "port": port, "users": [user]}]}
    elif p == "trojan":
        if not n.get("password"):
            return None
        outbound["settings"] = {"servers": [{"address": host, "port": port, "password": n["password"]}]}
    elif p == "ss":
        if not n.get("password") or not n.get("method") or n.get("plugin"):
            return None
        outbound["settings"] = {"servers": [{"address": host, "port": port,
                                               "method": n["method"], "password": n["password"]}]}

    if p != "ss":
        stream = _xray_stream(n)
        if stream is None:
            return None
        outbound["streamSettings"] = stream

    return {
        "log": {"loglevel": "error"},
        "inbounds": [{"listen": "127.0.0.1", "port": int(local_port), "protocol": "socks",
                       "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [outbound],
    }


def _xray_check(n, timeout=TIMEOUT):
    if not XRAY_BIN:
        return None
    port = _free_port()
    config = _xray_config(n, port)
    if config is None:
        return None
    text = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
    return _run_proxy_test([XRAY_BIN, "run", "-c"], text, port, timeout)


def _hysteria_check(n, timeout=HY2_TIMEOUT):
    """Runs the official Hysteria client and verifies real HTTPS egress."""
    if not HYSTERIA_BIN:
        return None
    raw = (n.get("raw") or "").strip()
    if not raw:
        return None
    low = raw.lower()
    if low.startswith("hy2://"):
        raw = "hysteria2://" + raw[len("hy2://"):]
    elif low.startswith("hy://"):
        raw = "hysteria2://" + raw[len("hy://"):]
    elif not low.startswith("hysteria2://"):
        return None
    port = _free_port()
    # JSON string syntax is also a valid YAML scalar; preserve the original URI
    # including SNI, TLS, ALPN and Salamander parameters.
    config = "server: %s\nsocks5:\n  listen: 127.0.0.1:%d\n" % (json.dumps(raw), port)
    return _run_proxy_test([HYSTERIA_BIN, "client"], config, port, timeout)


def is_alive(n, timeout=TIMEOUT):
    p = _proto(n)
    if p in _HY2_PROTOS:
        return _hysteria_check(n, HY2_TIMEOUT)
    if p in _XRAY_PROTOS:
        return _xray_check(n, timeout)
    # No protocol-aware probe installed: unknown, not an unverified TCP "alive".
    return None


def check_many(nodes, workers=WORKERS, timeout=TIMEOUT):
    from concurrent.futures import ThreadPoolExecutor
    res = {}
    if not nodes:
        return res
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(is_alive, n, timeout): _key(n) for n in nodes}
        for f, k in futs.items():
            try:
                value = f.result()
                res[k] = None if value is None else bool(value)
            except Exception:
                res[k] = None
    return res


# ------------------------------------------------------------------ filtering
def filter_nodes(nodes, prev_scan):
    """Returns (non_dead_nodes, dead_map, stats, confirmed_live_nodes)."""
    prev_scan = prev_scan or {}
    prev_dead = prev_scan.get("dead") or {}
    th = DEAD_THRESHOLD

    in_dead = [n for n in nodes if prev_dead.get(_key(n), 0) > 0]
    in_dead.sort(key=lambda n: -prev_dead.get(_key(n), 0))
    others = [n for n in nodes if prev_dead.get(_key(n), 0) == 0]
    salt = int(time.time() // ROTATE_PERIOD)
    others.sort(key=lambda n: hashlib.sha1(("%d|%s" % (salt, _key(n))).encode()).hexdigest())

    to_check = (in_dead + others)[:MAX_CHECKS]
    results = check_many(to_check)

    # Keep the all-zero UDP safety net for genuine probe/network outages.
    proto_state = {}
    for n in to_check:
        p = _proto(n)
        result = results.get(_key(n))
        if p in _UDP_PROTOS and result is not None:
            s = proto_state.setdefault(p, [0, 0])
            s[1] += 1
            if result:
                s[0] += 1
    suspect = {p for p, (alive, tot) in proto_state.items() if tot > 0 and alive == 0}

    new_dead = dict(prev_dead)
    newly_dead = 0
    for n in to_check:
        k = _key(n)
        result = results.get(k)
        if result is None:
            # Missing/failed test engine is not a server failure; don't carry a
            # stale quarantine into a run where that protocol cannot be tested.
            new_dead.pop(k, None)
            continue
        alive = result
        if _proto(n) in suspect:
            alive = True
        if alive:
            new_dead.pop(k, None)
        else:
            new_dead[k] = prev_dead.get(k, 0) + 1
            if new_dead[k] == th:
                newly_dead += 1

    present = {_key(n) for n in nodes}
    new_dead = {k: v for k, v in new_dead.items() if k in present}
    hard = {k for k, v in new_dead.items() if v >= th}
    filtered = [n for n in nodes if _key(n) not in hard]
    confirmed = [n for n in to_check
                 if results.get(_key(n)) is True and _proto(n) not in suspect and _key(n) not in hard]

    stats = {
        "checked": len(to_check),
        "alive": len(confirmed),
        "unknown": sum(1 for n in to_check if results.get(_key(n)) is None),
        "verified": len(confirmed),
        "dropped": len(nodes) - len(filtered),
        "newly_dead": newly_dead,
        "suspect_protos": sorted(suspect),
        "dead_tracked": len(new_dead),
        "probe_methods": {"xray_protocols": "full_https_through_socks" if XRAY_BIN else "unavailable",
                          "hysteria2": "full_https_through_official_client" if HYSTERIA_BIN else "unavailable"},
    }
    return filtered, new_dead, stats, confirmed


if __name__ == "__main__":
    import sys
    for hp in sys.argv[1:]:
        host, _, port = hp.rpartition(":")
        node = {"protocol": "vless", "host": host, "port": int(port or 443), "name": hp}
        print(hp, "->", "alive" if is_alive(node, 4) else "dead/unknown")
