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

import aggregator
import nodeparser
import subfetch


def load_env():
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except Exception:
        pass


def gather_new(texts, max_subs):
    """Из списка сообщений извлекает ноды + распаковывает URL-подписки (параллельно)."""
    warnings = []
    urls, seen = [], set()
    for t in texts:
        for u in nodeparser.extract_urls(t):
            if u not in seen:
                seen.add(u)
                urls.append(u)
    urls = urls[:max_subs]

    all_uris = []
    for t in texts:
        all_uris.extend(nodeparser.extract_uris(t))

    if urls:
        for u, data in subfetch.fetch_many(urls, timeout=10, max_workers=16):
            uris = subfetch.parse_subscription(data)
            if uris:
                all_uris.extend(uris)
            else:
                warnings.append("sub: no nodes at %s" % u)

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
        source = "tg/s/%s (последние %g ч)" % (tmscraper._normalize(channel), args.max_age)
        fresh, warnings = gather_new(texts, args.max_subs)
        print("Сообщений в окне: %d, новых нод: %d" % (len(texts), len(fresh)))

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

    # Liveness (выборочно): отсечь «мёртвые» ноды, чтобы они не попадали в подписку
    import liveness
    merged, dead_map, live_stats = liveness.filter_nodes(merged, prev_scan)
    if live_stats.get("dropped"):
        warnings.append("liveness: исключено мёртвых нод: %d" % live_stats["dropped"])
    print("Liveness: проверено=%d, живых=%d, исключено=%d (в треке мёртвых=%d)"
          % (live_stats["checked"], live_stats["alive"], live_stats["dropped"], live_stats["dead_tracked"]))
    if not merged:
        print("❌ После проверки живости годных нод не осталось — пуш отменён (остаётся последняя рабочая версия).")
        return 2

    files, meta = aggregator.build(merged, source=source, warnings=warnings, oldest_id=oldest_id,
                                   scan_extra={"dead": dead_map})
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
