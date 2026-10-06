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

_CHUNK_SPLIT = '<div class="tgme_widget_message_wrap'
_ID_RE = re.compile(r'data-post="[^"]*/(\d+)"')
_TEXT_RE = re.compile(r'class="tgme_widget_message_text[^"]*"[^>]*>([\s\S]*?)</div>')
_UA = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
    "Accept-Language": "en-US,en;q=0.9",
}


def _clean(s):
    s = re.sub(r"<br\s*/?>", "\n", s, flags=re.I)
    s = re.sub(r"<[^>]+>", "", s)
    return html.unescape(s).strip()


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
    """Возвращает [(msg_id, text), ...] в порядке от старых к новым на странице."""
    chunks = page_html.split(_CHUNK_SPLIT)
    out = []
    for chunk in chunks[1:]:
        idm = _ID_RE.search(chunk)
        if not idm:
            continue
        txt = _TEXT_RE.search(chunk)
        if not txt:
            continue  # сообщение без текста (только фото/видео)
        out.append((idm.group(1), _clean(txt.group(1))))
    out.sort(key=lambda x: int(x[0]))
    return out


def collect(username, lookback=200, max_pages=60, delay=1.0, stop_id=0):
    """Читает последние `lookback` сообщений публичного канала.

    Возвращает (texts, oldest_id). `stop_id` — не читать глубже этого id
    (уже обработано в прошлых запусках), чтобы экономить запросы к t.me/s/.
    """
    import requests  # noqa: F401
    ch = _normalize(username)
    if not ch:
        raise SystemExit("Укажи TG_CHANNEL — @username публичного канала")
    base = "https://t.me/s/%s" % ch
    url = base
    seen = {}
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
        for mid, text in batch:
            if mid not in seen:
                seen[mid] = text
                added += 1
        min_id = min(int(m) for m, _ in batch)
        if len(seen) >= lookback or added == 0 or min_id <= 1 or (stop_id and min_id <= stop_id):
            break
        url = "%s/%d" % (base, min_id)  # идём дальше вглубь
        time.sleep(delay)
    texts = [seen[k] for k in sorted(seen, key=int)]
    oldest_id = min((int(k) for k in seen), default=0)
    return texts[:lookback], oldest_id
