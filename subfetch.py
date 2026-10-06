"""
subfetch.py — скачивает URL-подписки и распаковывает их в список node-URI.

Многие каналы кидают не сами ноды, а ссылку на подписку (sub.example.com/sub?token=..).
Такой линк отдаёт либо plain-text список URI, либо base64-блок. Мы пробуем
несколько User-Agent (некоторые серверы требуют "subscription-useragent"),
распаковываем gzip, проверяем на base64 и возвращаем только те результаты,
которые реально содержат node-URI. HTTPS-сертификаты проверяются стандартно.
"""
import base64
import gzip
import re

import nodeparser

_UAS = [
    "clash-verge/v2.0",
    "clash-meta/v1.0",
    "v2rayN/6.40",
    "sing-box/1.9",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
]
_HEADS = [
    {"User-Agent": "clash-verge/v2.0", "Accept": "*/*"},
    {"User-Agent": "clash-meta/v1.0", "Accept": "*/*", "Subscription-Useragent": "clash-verge/v2.0"},
    {"User-Agent": _UAS[4], "Accept": "*/*"},
]

_SCHEME_HINT = re.compile(r"(?i)\b(vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|shadowtls|wireguard|ssh)://")
_MAX_BYTES = 3_000_000


def fetch_url(url, timeout=8):
    """Возвращает bytes тела подписки или None.

    Мёртвые линки (402/404/502/…) не перебираем по User-Agent — это экономит время.
    Повтор с другим UA только при 401/403 (сервер, возможно, требует спец. UA) и при ошибке сети.
    """
    import requests  # lazy: чтобы selftest работал без установленного requests
    for h in _HEADS:
        try:
            r = requests.get(url, headers=h, timeout=timeout, allow_redirects=True)
            if 200 <= r.status_code < 300:
                data = r.content[:_MAX_BYTES]
                if data[:2] == b"\x1f\x8b":
                    try:
                        data = gzip.decompress(data)
                    except Exception:
                        pass
                return data
            if r.status_code in (401, 403):
                continue  # попробуем другой UA
            break  # 402/404/502/… — мёртвый линк, повторять бессмысленно
        except Exception:  # noqa: BLE001
            continue
    return None


def fetch_many(urls, timeout=8, max_workers=16):
    """Параллельная загрузка списка URL. Возвращает [(url, data_or_None), ...]."""
    import concurrent.futures as cf
    def _one(u):
        return u, fetch_url(u, timeout=timeout)
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        return list(ex.map(_one, urls))


def _to_text(data):
    if not data:
        return ""
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(enc)
        except Exception:
            pass
    return data.decode("utf-8", "replace")


def _b64_to_text(s):
    s = (s or "").strip()
    if not s or len(s) < 8:
        return None
    compact = re.sub(r"\s+", "", s)
    if re.search(r"[^A-Za-z0-9+/=_-]", compact):
        return None
    if len(compact) % 4 == 1:
        return None
    pad = compact + "=" * (-len(compact) % 4)
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = fn(pad)
            txt = raw.decode("utf-8")
        except Exception:
            continue
        if txt and ("://" in txt or "\n" in txt) and _SCHEME_HINT.search(txt):
            return txt
    return None


def parse_subscription(data):
    """data: bytes -> list[str] raw node URI (или [])."""
    if data is None:
        return []
    text = _to_text(data)
    candidates = [text.strip()]
    b1 = _b64_to_text(text)
    if b1:
        candidates.append(b1)
    if b1:
        b2 = _b64_to_text(b1)
        if b2:
            candidates.append(b2)
    for c in candidates:
        if c and _SCHEME_HINT.search(c):
            return nodeparser.extract_uris(c)
    return []
