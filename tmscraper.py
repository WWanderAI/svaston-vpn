"""
tmscraper.py — чтение ПУБЛИЧНОГО канала через веб-превью t.me/s/<имя>.

НЕ нужны api_id / api_hash / вход / бот — только @username публичного канала.
Страница отдаёт ~20 последних сообщений; дальше идём назад по id сообщения
(t.me/s/<имя>/<id>), пока не наберём lookback сообщений или не дойдём до начала.

Ограничения: только публичные каналы; глубина ограничена (старые сообщения
Telegram периодически убирает из веб-превью). Накопление нод между запусками
обеспечивает nodes.json в репо, поэтому ограниченная история не критична.
"""
import html
import re
import time
from datetime import datetime, timedelta, timezone

_CHUNK_SPLIT = '<div class="tgme_widget_message_wrap'
_ID_RE = re.compile(r'data-post="[^"]*/(\d+)"')
_TEXT_RE = re.compile(r'class="tgme_widget_message_text[^"]*"[^>]*>([\s\S]*?)</div>')
_TIME_RE = re.compile(r'<time datetime="([^"]+)"')
_UA = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
    "Accept-Language": "en-US,en;q=0.9",
}


def _clean(s):
    s = re.sub(r"<br\s*/?>", "\n", s, flags=re.I)
    s = re.sub(r"<[^>]+>", "", s)
    return html.unescape(s).strip()


def _parse_time(s):
    """'2026-10-06T13:00:00+00:00' / '...Z' -> aware datetime (UTC) или None."""
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _normalize(username):
    u = (username or "").strip()
    u = re.sub(r"^https?://t\.me/", "", u)
    u = re.sub(r"^https?://telegram\./d/", "", u)
    if u.startswith("s/"):
        u = u[2:]
    u = u.split("/")[0]
    return u.lstrip("@")


def _fetch(url):
    import requests
    r = requests.get(url, headers=_UA, timeout=25)
    r.raise_for_status()
    return r.text


def _page_messages(page_html):
    """Возвращает [(msg_id, text, time_str), ...] от старых к новым на странице."""
    chunks = page_html.split(_CHUNK_SPLIT)
    out = []
    for chunk in chunks[1:]:
        idm = _ID_RE.search(chunk)
        if not idm:
            continue
        txt = _TEXT_RE.search(chunk)
        if not txt:
            continue  # сообщение без текста (только фото/видео)
        timem = _TIME_RE.search(chunk)
        out.append((idm.group(1), _clean(txt.group(1)), timem.group(1) if timem else ""))
    out.sort(key=lambda x: int(x[0]))
    return out


def collect(username, lookback=300, max_age_hours=24, max_pages=60, delay=1.0):
    """Читает сообщения публичного канала, уходя назад до отсечки по времени.

    Возвращает (messages, oldest_id), где messages = [(text, time_str), ...]
    от старых к новым — только за последние `max_age_hours` (0 = без отсечки).
    `lookback` — страховочный предел количества сообщений.
    """
    import requests  # noqa: F401
    ch = _normalize(username)
    if not ch:
        raise SystemExit("Укажи TG_CHANNEL — @username публичного канала")
    base = "https://t.me/s/%s" % ch
    url = base
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)) \
        if max_age_hours and max_age_hours > 0 else None
    seen = {}  # mid -> (text, time_str)
    for _ in range(max_pages):
        page = _fetch(url)
        batch = _page_messages(page)
        if not batch and url == base:
            raise SystemExit(
                "Не удалось прочитать %s. Проверь, что канал ПУБЛИЧНЫЙ и username верный. "
                "Приватный канал так не читается (нужен вход через аккаунт)." % ch
            )
        if not batch:
            break
        added = 0
        for mid, text, tstr in batch:
            if mid not in seen:
                seen[mid] = (text, tstr)
                added += 1
        min_id = min(int(m) for m, _, _ in batch)
        reached_cutoff = False
        if cutoff is not None:
            oldest = min(batch, key=lambda x: int(x[0]))
            odt = _parse_time(oldest[2])
            if odt is not None and odt < cutoff:
                reached_cutoff = True
        if len(seen) >= lookback or added == 0 or min_id <= 1 or reached_cutoff:
            break
        url = "%s/%d" % (base, min_id)  # идём дальше вглубь
        time.sleep(delay)
    msgs = []
    for mid in sorted(seen, key=int):
        text, tstr = seen[mid]
        dt = _parse_time(tstr)
        if cutoff is None or dt is None or dt >= cutoff:
            msgs.append((text, tstr))
    oldest_id = min((int(k) for k in seen), default=0)
    return msgs, oldest_id
