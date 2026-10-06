"""
main.py — точка входа.

По умолчанию читает ПУБЛИЧНЫЙ канал через t.me/s/<имя> (без api_id/api_hash/входа).

  python main.py                          # локально, без пуша, пишет в ./out
  python main.py --lookback 300           # читать 300 последних сообщений
  python main.py --push                   # пушить в GitHub (в Actions)
  python main.py --nodes-file X.json      # офлайн: из готового nodes.json (без сети)
"""
import argparse
import json
import os
import sys
from urllib.parse import urlsplit

import aggregator
import nodeparser
import subfetch


def load_env():
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except Exception:
        pass


def public_feed_urls(value=None):
    """Читает только публичные HTTPS raw-фиды GitHub из FREE_FEEDS."""
    if value is None:
        value = os.environ.get("FREE_FEEDS", "")
    urls, warnings = [], []
    for url in (value or "").replace(",", " ").replace(";", " ").split():
        url = url.strip()
        if not url:
            continue
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname != "raw.githubusercontent.com" or not parsed.path.startswith("/"):
            warnings.append("FREE_FEEDS: пропущен небезопасный/неподдерживаемый URL: %s" % url[:120])
            continue
        if url not in urls:
            urls.append(url)
    return urls, warnings


def _spread_limit(items, limit):
    """Ограничивает большой фид равномерной выборкой по всему списку."""
    limit = max(0, int(limit))
    if limit == 0:
        return []
    if len(items) <= limit:
        return items
    if limit == 1:
        return [items[len(items) // 2]]
    last = len(items) - 1
    indices = [(i * last) // (limit - 1) for i in range(limit)]
    return [items[i] for i in indices]


def gather_new(texts, max_subs, public_feeds=None, public_feed_limit=250):
    """Собирает прямые ноды и распаковывает подписки/публичные GitHub-фиды."""
    warnings = []
    tg_urls, seen = [], set()
    for t in texts:
        for u in nodeparser.extract_urls(t):
            if u not in seen:
                seen.add(u)
                tg_urls.append(u)
    tg_urls = tg_urls[:max(0, int(max_subs))]

    feeds = []
    for u in public_feeds or []:
        if u not in seen and u not in feeds:
            feeds.append(u)
    feed_set = set(feeds)
    urls = tg_urls + feeds

    all_uris = []
    for t in texts:
        all_uris.extend(nodeparser.extract_uris(t))

    if urls:
        for u, data in subfetch.fetch_many(urls, timeout=10, max_workers=16):
            uris = subfetch.parse_subscription(data)
            if u in feed_set:
                if uris:
                    before = len(uris)
                    uris = _spread_limit(uris, public_feed_limit)
                    label = urlsplit(u).path.rsplit("/", 1)[-1] or "GitHub"
                    print("Public feed %s: URI=%d, sample=%d" % (label, before, len(uris)))
                else:
                    warnings.append("public feed: no nodes at %s" % u)
            elif not uris:
                warnings.append("sub: no nodes at %s" % u)
            if uris:
                all_uris.extend(uris)

    nodes = [nodeparser.parse_uri(u) for u in all_uris]
    return nodes, warnings


def merge(master, fresh):
    seen = {}
    for n in list(master) + list(fresh):
        if not isinstance(n, dict) or not n.get("raw"):
            continue
        seen[nodeparser.node_key(n)] = n
    return list(seen.values())


def write_local(files):
    for p, c in files.items():
        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(c)


def main():
    load_env()
    ap = argparse.ArgumentParser(description="VPN subscription aggregator (public t.me/s)")
    ap.add_argument("--push", action="store_true", help="пушить результат в GitHub")
    ap.add_argument("--channel", default=os.environ.get("TG_CHANNEL"),
                    help="@username / username публичного канала (или TG_CHANNEL)")
    ap.add_argument("--lookback", type=int, default=int(os.environ.get("TG_LOOKBACK", "300")))
    ap.add_argument("--max-age", type=float, default=float(os.environ.get("TG_MAX_AGE_HOURS", "24")),
                    help="только сообщения за последние N часов (0 = без отсечки; по умолчанию 24)")
    ap.add_argument("--max-subs", type=int, default=int(os.environ.get("SUB_FETCH_MAX", "20")))
    ap.add_argument("--nodes-file", default=None, help="офлайн: стартовый nodes.json вместо чтения TG")
    args = ap.parse_args()

    gp = None
    master = []   # накопления старых нод нет: набор = окно за последние N часов
    oldest_id = 0
    prev_scan = {}
    if args.push:
        import github_push
        gp = github_push.make_pusher()
        gp.resolve()
        # читаем только meta (для liveness dead-map), nodes.json в master не несём
        existing_meta = gp.read_file("out/meta.json")
        if existing_meta:
            try:
                prev_scan = json.loads(existing_meta).get("scan", {}) or {}
            except Exception:
                prev_scan = {}

    source = ""
    fresh = []
    warnings = []
    public_feeds = []
    if args.nodes_file:
        with open(args.nodes_file, encoding="utf-8") as f:
            master = json.load(f)
        source = "offline:%s" % os.path.basename(args.nodes_file)
    else:
        import tmscraper
        channel = args.channel
        if not channel:
            raise SystemExit("Укажи канал: --channel @username или TG_CHANNEL в .env")
        msgs, oldest_id = tmscraper.collect(channel, lookback=args.lookback, max_age_hours=args.max_age)
        texts = [t for t, _ in msgs]
        public_feeds, feed_warnings = public_feed_urls()
        source = "tg/s/%s (последние %g ч)" % (tmscraper._normalize(channel), args.max_age)
        if public_feeds:
            source += " + %d публичных GitHub-фида" % len(public_feeds)
        try:
            public_feed_limit = max(0, int(os.environ.get("FREE_FEED_NODE_CAP", "250")))
        except ValueError:
            public_feed_limit = 250
            feed_warnings.append("FREE_FEED_NODE_CAP задан неверно; использовано значение 250")
        fresh, scrape_warnings = gather_new(texts, args.max_subs, public_feeds, public_feed_limit)
        warnings = feed_warnings + scrape_warnings
        print("Сообщений в окне: %d, новых нод: %d, публичных GitHub-фидов: %d"
              % (len(texts), len(fresh), len(public_feeds)))

    merged = merge(master, fresh)

    # Автопроверка (1/2): отсекаем негодные ноды (нет host/port) ДО сборки,
    # чтобы они не попали ни в подписку, ни в конфиги.
    import validate
    good, bad = validate.split_nodes(merged)
    if bad:
        warnings.append("автопроверка: отброшено негодных нод (нет host/port): %d" % len(bad))
    if not good:
        print("❌ Годных нод нет — в репозиторий ничего НЕ загружаем.")
        for b in bad[:5]:
            print("   - %s" % str(b.get("raw"))[:120])
        return 2
    merged = good

    # Протокольная проверка выборки: публикуем только ноды, прошедшие HTTPS-запрос
    # через реальный клиент. Открытый TCP-порт сам по себе не означает рабочий VPN.
    import liveness
    candidate_total = len(merged)
    _not_dead, dead_map, live_stats, confirmed = liveness.filter_nodes(merged, prev_scan)
    live_stats["candidates"] = candidate_total
    try:
        publish_max = max(0, int(os.environ.get("PUBLISH_MAX", "0")))
    except ValueError:
        publish_max = 0
        warnings.append("PUBLISH_MAX задан неверно; лимит публикации отключён")
    if publish_max and len(confirmed) > publish_max:
        live_stats["verified_before_cap"] = len(confirmed)
        confirmed = confirmed[:publish_max]  # liveness sorts by measured RTT
        live_stats["verified"] = len(confirmed)
        live_stats["publish_cap"] = publish_max
    if live_stats.get("dropped"): 
        warnings.append("liveness: подтверждённо мёртвых исключено: %d" % live_stats["dropped"])
    if live_stats.get("high_latency"):
        warnings.append("liveness: исключено по задержке выше эффективного лимита %d мс: %d"
                        % (live_stats["effective_latency_limit_ms"], live_stats["high_latency"]))
    print("Liveness: кандидатов=%d, проверено=%d, туннель OK=%d, <=%dмс=%d, >лимита=%d, без ответа=%d, unknown=%d"
          % (candidate_total, live_stats["checked"], live_stats["alive"],
             live_stats["effective_latency_limit_ms"], live_stats["verified"],
             live_stats["high_latency"], live_stats["no_response"], live_stats["unknown"]))
    if not confirmed:
        print("❌ Ни одна нода не прошла настоящий тест через туннель — пуш отменён; прежняя подписка сохранена.")
        return 2
    if len(confirmed) < candidate_total:
        warnings.append("liveness: в подписку включены только реально проверенные узлы: %d из %d"
                        % (len(confirmed), candidate_total))

    files, meta = aggregator.build(confirmed, source=source, warnings=warnings, oldest_id=oldest_id,
                                   scan_extra={"dead": dead_map})
    meta["public_feeds"] = public_feeds
    meta["candidate_total"] = candidate_total
    meta["liveness"] = live_stats

    # Автопроверка (2/2): финальная структурная проверка готовых артефактов.
    ok, report = validate.validate_outputs(files, meta)
    meta["validation"] = {"ok": ok, "errors": report["errors"],
                          "warnings": report["warnings"], "counts": report["counts"]}
    files["out/meta.json"] = json.dumps(meta, ensure_ascii=False, indent=2)
    print(validate.format_report(report))
    if not ok:
        print("❌ Конфиги не прошли проверку — пуш отменён (остаётся последняя рабочая версия).")
        return 2

    if args.push:
        if gp.needs_push(files, aggregator.MARKER):
            sha = gp.do_push(files, "chore: refresh VPN nodes (%d total)" % meta["total"])
            print("Push OK: commit %s, nodes=%d" % (sha[:12], meta["total"]))
        else:
            print("Набор нод не изменился — пуш пропущен.")
    else:
        write_local(files)
        print("Записано %d файлов в ./out, nodes=%d" % (len(files), meta["total"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
