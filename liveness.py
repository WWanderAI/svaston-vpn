"""
liveness.py — лёгкая выборочная проверка живости нод перед пушем.

  * за прогон проверяется только выборка (приоритет — кандидаты в dead, затем ротация);
  * TCP-ноды проверяются соединением с host:port;
  * Hysteria2 проверяется настоящим официальным клиентом (HYSTERIA_BIN), а не
    некорректным «сырым TLS-пакетом» по UDP;
  * нода исключается после двух последовательных подтверждённых неудач;
  * непроверяемая нода не считается мёртвой; одна ошибка не выбрасывает живую ноду;
  * если UDP-протокол в выборке совсем не отвечает, срабатывает safety-net и
    целиком этот протокол не выключается.

Переменные окружения: LIVENESS_TIMEOUT, LIVENESS_WORKERS, LIVENESS_MAX,
LIVENESS_DEAD, LIVENESS_ROTATE, HY2_CHECK_TIMEOUT, HYSTERIA_BIN.
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

TIMEOUT = float(os.environ.get("LIVENESS_TIMEOUT", "4"))
WORKERS = int(os.environ.get("LIVENESS_WORKERS", "30"))
MAX_CHECKS = int(os.environ.get("LIVENESS_MAX", "150"))
DEAD_THRESHOLD = int(os.environ.get("LIVENESS_DEAD", "2"))
ROTATE_PERIOD = int(os.environ.get("LIVENESS_ROTATE", "300"))
HY2_TIMEOUT = float(os.environ.get("HY2_CHECK_TIMEOUT", "6"))
HYSTERIA_BIN = os.environ.get("HYSTERIA_BIN") or shutil.which("hysteria") or ""

_TCP_PROTOS = {"vless", "vmess", "trojan", "shadowtls", "ss", "ssr", "amnezia", "socks5", "ssh"}
_UDP_PROTOS = {"hysteria2", "hy2", "hy", "tuic", "wireguard"}
_HY2_PROTOS = {"hysteria2", "hy2", "hy"}
_GENERIC_UDP = b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00"


def _key(n):
    import nodeparser
    return repr(nodeparser.node_key(n))


def _proto(n):
    return (n.get("protocol") or "").lower()


def _tcp_check(host, port, timeout):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def _udp_check(host, port, payload, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(payload, (host, int(port)))
        try:
            s.recv(4096)
            return True
        except socket.timeout:
            return False
        finally:
            s.close()
    except Exception:
        return False


def _hysteria_check(n, timeout=HY2_TIMEOUT):
    """Полноценный QUIC/TLS/auth handshake через официальный Hysteria client.

    Возвращает True/False, если клиент установлен; None — если зонд недоступен,
    тогда узел не штрафуется и остаётся в подписке.
    """
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

    # JSON-строка — корректный скаляр YAML; URI в конфиге не теряет obfs, SNI,
    # insecure и прочие параметры. Временный файл содержит credentials и удаляется.
    config = "server: %s\nsocks5:\n  listen: 127.0.0.1:0\n" % json.dumps(raw)
    fd = None
    path = None
    proc = None
    try:
        fd, path = tempfile.mkstemp(prefix="hy2-probe-", suffix=".yaml")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None
            f.write(config)
        proc = subprocess.Popen(
            [HYSTERIA_BIN, "client", "-c", path, "--disable-update-check", "-l", "info"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        deadline = time.monotonic() + max(1.0, float(timeout))
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return False
            ready, _, _ = select.select([proc.stdout], [], [], max(0.0, deadline - time.monotonic()))
            if not ready:
                break
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    return False
                continue
            if "connected to server" in line.lower():
                return True
        return False
    except (FileNotFoundError, PermissionError, OSError, ValueError):
        # Ошибка самого зонда/окружения — не объявлять сервер мёртвым.
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
            try:
                if proc.stdout:
                    proc.stdout.close()
            except Exception:
                pass
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def is_alive(n, timeout=TIMEOUT):
    host = (n.get("host") or "").strip()
    try:
        port = int(n.get("port") or 0)
    except Exception:
        port = 0
    if not host or port <= 0:
        return False
    p = _proto(n)
    network = (n.get("network") or "").lower()
    if p in _HY2_PROTOS:
        return _hysteria_check(n, HY2_TIMEOUT)
    if p in _UDP_PROTOS or network in ("quic", "udp"):
        return _udp_check(host, port, _GENERIC_UDP, timeout)
    return _tcp_check(host, port, timeout)


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
                # Неизвестный сбой в зонде не превращаем в ложный dead.
                res[k] = None
    return res


# ------------------------------------------------------------------ filter
def filter_nodes(nodes, prev_scan):
    """Возвращает (filtered_nodes, dead_map, stats)."""
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

    # Safety-net: если в выборке ни один узел UDP-протокола не ответил,
    # не выключаем весь протокол из-за возможной проблемы в среде проверки.
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
            # Зонд недоступен: не накапливаем ошибки и не сохраняем stale dead.
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
    unknown = sum(1 for n in to_check if results.get(_key(n)) is None)
    stats = {
        "checked": len(to_check),
        "alive": sum(1 for n in to_check if results.get(_key(n)) is True or _proto(n) in suspect),
        "unknown": unknown,
        "dropped": len(nodes) - len(filtered),
        "newly_dead": newly_dead,
        "suspect_protos": sorted(suspect),
        "dead_tracked": len(new_dead),
        "probe_methods": {
            "tcp": "connect",
            "hysteria2": "official-client" if HYSTERIA_BIN else "unavailable",
            "other_udp": "response",
        },
    }
    return filtered, new_dead, stats


if __name__ == "__main__":
    # Ручной TCP-зонд: python liveness.py host:port …
    import sys
    for hp in sys.argv[1:]:
        host, _, port = hp.rpartition(":")
        node = {"protocol": "vless", "host": host, "port": int(port or 443), "name": hp}
        print(hp, "->", "alive" if is_alive(node, 4) else "dead")
