"""
liveness.py — лёгкая ВЫБОРОЧНАЯ проверка живости нод перед пушем.

Отсекает «мёртвые» ноды (не отвечают), чтобы они не попадали в подписку
(например, узлы с 0ms в клиенте). Принципы:
  * каждый прогон проверяем только ВЫБОРКУ (не все 400+) — чтобы не бить
    лимиты и время. Приоритет: ноды с предыдущей неудачей, затем ротация
    по остальным (соль меняется каждые ROTATE_PERIOD сек — за несколько
    прогонов покрываем все);
  * узел считается мёртвым только после DEAD_THRESHOLD последовательных
    провалов (по умолчанию 2) — один сбой не выкидывает живую ноду;
  * при успешной проверке узел «воскрешается» (счётчик сбрасывается);
  * состояние (dead) живёт в out/meta.json → scan.dead и переживает запуски.

Методы зонда (все «мягкие»: неоднозначно → считаем живым, лучше не потерять живую ноду):
  * TCP-протоколы (vless/vmess/trojan/ss/ssr/…): TCP-соединение на host:port;
  * hysteria2: корректный «первый пакет» Hysteria2 (magic + TLS ClientHello) по UDP;
  * прочие UDP (tuic/wireguard/…): лучший UDP-зонд (любой ответ = жив);
  * страховка: если проверяемый UDP-протокол не отозвался совсем (0 живых из
    проверенных), считаем проблему в зонде и НЕ выключаем весь протокол.

Запуск локально (самопроверка зонда по конкретным хостам) — см. __main__.
"""
import hashlib
import os
import socket
import time

TIMEOUT = float(os.environ.get("LIVENESS_TIMEOUT", "4"))
WORKERS = int(os.environ.get("LIVENESS_WORKERS", "30"))
MAX_CHECKS = int(os.environ.get("LIVENESS_MAX", "150"))
DEAD_THRESHOLD = int(os.environ.get("LIVENESS_DEAD", "2"))
ROTATE_PERIOD = int(os.environ.get("LIVENESS_ROTATE", "300"))

_TCP_PROTOS = {"vless", "vmess", "trojan", "shadowtls", "ss", "ssr", "amnezia", "socks5", "ssh"}
_UDP_PROTOS = {"hysteria2", "hy2", "hy", "tuic", "wireguard"}


def _key(n):
    import nodeparser
    return repr(nodeparser.node_key(n))


def _proto(n):
    return (n.get("protocol") or "").lower()


# ---------------------------------------------------------------- zone ping
def _client_hello(sni=""):
    import os as _os
    inner = b"\x03\x03" + _os.urandom(32) + b"\x00"
    inner += b"\x00\x06" + b"\x13\x01\x13\x02\x13\x03\xc0\x2f\xc0\x2b"   # cipher suites (TLS1.3+1.2)
    inner += b"\x01\x00"                                                  # compression: null
    exts = b""
    sv = b"\x03\x04"                                                      # supported_versions: TLS1.3
    exts += b"\x00\x27" + (len(sv) + 1).to_bytes(2, "big") + bytes([len(sv) + 1]) + sv
    if sni:                                                               # server_name
        nm = sni.encode()
        entry = b"\x03" + len(nm).to_bytes(2, "big") + nm
        lst = len(entry).to_bytes(2, "big") + entry
        exts += b"\x00\x00" + len(lst).to_bytes(2, "big") + lst
    inner += len(exts).to_bytes(2, "big") + exts
    hs = b"\x01" + len(inner).to_bytes(3, "big") + inner
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def _hy2_first_packet(sni=""):
    # [header 0x02][magic 20 5e 29 53][len:2][TLS 1.3 ClientHello]
    hello = _client_hello(sni)
    return bytes([0x02]) + b"\x20\x5e\x29\x53" + len(hello).to_bytes(2, "big") + hello


_GENERIC_UDP = b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00"


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
    if p in _UDP_PROTOS or network in ("quic", "udp"):
        if p in ("hysteria2", "hy2", "hy"):
            sni = n.get("sni") or n.get("host_header") or host or ""
            return _udp_check(host, port, _hy2_first_packet(sni), timeout)
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
                res[k] = bool(f.result())
            except Exception:
                res[k] = False
    return res


# ------------------------------------------------------------------ filter
def filter_nodes(nodes, prev_scan):
    """Возвращает (filtered_nodes, dead_map, stats).

    Dead-кандидаты (с учётом уже «мёртвых») всегда проверяются с приоритетом —
    так они могут «ожить» и вернуться. Общий лимит на прогон: MAX_CHECKS.
    """
    prev_scan = prev_scan or {}
    prev_dead = prev_scan.get("dead") or {}
    th = DEAD_THRESHOLD

    in_dead = [n for n in nodes if prev_dead.get(_key(n), 0) > 0]
    in_dead.sort(key=lambda n: -prev_dead.get(_key(n), 0))   # наибольшие счётчики — сначала
    others = [n for n in nodes if prev_dead.get(_key(n), 0) == 0]
    salt = int(time.time() // ROTATE_PERIOD)
    others.sort(key=lambda n: hashlib.sha1(("%d|%s" % (salt, _key(n))).encode()).hexdigest())

    to_check = (in_dead + others)[:MAX_CHECKS]
    results = check_many(to_check)

    # страховка от ложного отключения целого UDP-протокола (проблема зонда)
    proto_state = {}
    for n in to_check:
        p = _proto(n)
        if p in _UDP_PROTOS:
            s = proto_state.setdefault(p, [0, 0])
            s[1] += 1
            if results.get(_key(n)):
                s[0] += 1
    suspect = {p for p, (alive, tot) in proto_state.items() if tot > 0 and alive == 0}

    new_dead = dict(prev_dead)
    newly_dead = 0
    for n in to_check:
        k = _key(n)
        alive = results.get(k, False)
        if _proto(n) in suspect:
            alive = True  # зонд, видимо, не дозвонился до протокола — не выключаем
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

    stats = {"checked": len(to_check),
             "alive": sum(1 for n in to_check if results.get(_key(n)) or _proto(n) in suspect),
             "dropped": len(nodes) - len(filtered), "newly_dead": newly_dead,
             "suspect_protos": sorted(suspect), "dead_tracked": len(new_dead)}
    return filtered, new_dead, stats


if __name__ == "__main__":
    # быстрый ручной зонд: python liveness.py host:port host:port …
    import sys
    for hp in sys.argv[1:]:
        host, _, port = hp.rpartition(":")
        node = {"protocol": "vless", "host": host, "port": int(port or 443), "name": hp}
        print(hp, "->", "alive" if is_alive(node, 4) else "dead")
