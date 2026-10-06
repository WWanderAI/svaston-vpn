"""
validate.py — автопроверка VPN-конфигов ПЕРЕД загрузкой в репозиторий.

Два уровня:
  1) split_nodes(nodes) -> (good, bad)
       Отсекает ноды, чей raw-URI не пригоден (нет host/port). Грязные ноды
       НЕ попадают в подписку/конфиги.
  2) validate_outputs(files, meta) -> (ok, report)
       Финальная структурная проверка готовых артефактов (nodes.json / sub /
       b64 / singbox / clash). Если артефакт не парсится или пуст — ok=False,
       и пуш НЕ выполняется (в репо остаётся последняя рабочая версия).

CLI (проверить готовую папку out/):
  python validate.py out
"""
import base64
import json
import os

import nodeparser

MIN_NODES_WARN = 5   # меньше — пишем предупреждение (не блокируем)


def usable(n):
    """Можно ли использовать ноду: есть ли у raw-URI рабочий host (+port)."""
    if not isinstance(n, dict) or not n.get("raw"):
        return False
    host = (n.get("host") or "").strip()
    proto = (n.get("protocol") or "").lower()
    try:
        port = int(n.get("port") or 0)
    except Exception:
        port = 0
    if proto == "wireguard":
        return bool(host)  # у wireguard порт может быть внутри endpoint
    return bool(host) and 1 <= port <= 65535


def split_nodes(nodes):
    good, bad = [], []
    for n in nodes:
        (good if usable(n) else bad).append(n)
    return good, bad


def _port_ok(p):
    try:
        return 1 <= int(p) <= 65535
    except Exception:
        return False


def validate_outputs(files, meta=None):
    """Структурная проверка готовых файлов. Возвращает (ok, report)."""
    errors, warnings = [], []
    counts = {}
    meta = meta or {}

    # --- nodes.json -------------------------------------------------------
    nodes = None
    if "out/nodes.json" in files:
        try:
            nodes = json.loads(files["out/nodes.json"])
            if not isinstance(nodes, list):
                raise ValueError("not a list")
        except Exception as e:
            errors.append("out/nodes.json: не парсится как JSON (%s)" % e)
            nodes = None
        if isinstance(nodes, list) and not nodes:
            errors.append("out/nodes.json: пустой список нод")
    else:
        errors.append("нет out/nodes.json")
    counts["nodes"] = len(nodes) if isinstance(nodes, list) else 0

    # --- sub/combined.txt -------------------------------------------------
    combined = files.get("out/sub/combined.txt", "")
    lines = [l.strip() for l in combined.splitlines() if l.strip()]
    counts["sub_uris"] = len(lines)
    bad_lines = []
    for l in lines:
        if "://" not in l:
            bad_lines.append(l)
            continue
        if not usable(nodeparser.parse_uri(l)):
            bad_lines.append(l)
    if not lines:
        errors.append("out/sub/combined.txt: пусто (0 нод в подписке)")
    if bad_lines:
        for bl in bad_lines[:5]:
            errors.append("combined.txt: негодный URI: %s" % bl[:120])
        if len(bad_lines) > 5:
            errors.append("combined.txt: ещё негодных URI: %d" % (len(bad_lines) - 5))

    # --- sub/b64.txt ------------------------------------------------------
    b64 = files.get("out/sub/b64.txt", "")
    if b64:
        try:
            dec = base64.b64decode(b64.encode()).decode("utf-8", "replace")
            if dec != combined:
                errors.append("out/sub/b64.txt: декодированный текст не совпадает с combined.txt")
        except Exception as e:
            errors.append("out/sub/b64.txt: невалидный base64 (%s)" % e)
    else:
        errors.append("нет out/sub/b64.txt")

    # --- per-node files ---------------------------------------------------
    n_nodefiles = sum(1 for p in files if p.startswith("out/nodes/") and p.endswith(".txt"))
    counts["node_files"] = n_nodefiles
    if isinstance(nodes, list) and nodes and n_nodefiles != len(nodes):
        warnings.append("out/nodes/: файлов %d != нод %d" % (n_nodefiles, len(nodes)))

    # --- singbox ----------------------------------------------------------
    if "out/singbox/config.json" in files:
        try:
            sb = json.loads(files["out/singbox/config.json"])
            obs = sb.get("outbounds") or []
            servers = [o for o in obs if isinstance(o, dict) and o.get("server")]
            counts["singbox_outbounds"] = len(servers)
            if not servers:
                errors.append("out/singbox/config.json: нет ни одного серверного outbound")
            for o in servers:
                if not _port_ok(o.get("server_port", 0)):
                    warnings.append("singbox: невалидный server_port у %s" % o.get("tag"))
        except Exception as e:
            errors.append("out/singbox/config.json: не парсится как JSON (%s)" % e)
    else:
        warnings.append("singbox: конфиг не сгенерирован (нет совместимых нод)")

    # --- clash ------------------------------------------------------------
    if "out/clash/config.yaml" in files:
        try:
            import yaml
            cl = yaml.safe_load(files["out/clash/config.yaml"])
            prox = (cl or {}).get("proxies") or []
            counts["clash_proxies"] = len(prox)
            if not prox:
                errors.append("out/clash/config.yaml: пустой список proxies")
            for pr in prox:
                if not (isinstance(pr, dict) and pr.get("server") and _port_ok(pr.get("port", 0))):
                    warnings.append("clash: невалидный прокси %s"
                                    % (pr.get("name") if isinstance(pr, dict) else pr))
        except Exception as e:
            errors.append("out/clash/config.yaml: не парсится как YAML (%s)" % e)
    else:
        warnings.append("clash: конфиг не сгенерирован (нет совместимых нод)")

    # --- счётчики ---------------------------------------------------------
    if counts.get("nodes") and counts.get("sub_uris") and counts["nodes"] != counts["sub_uris"]:
        warnings.append("счётчики: nodes.json=%d != combined=%d" % (counts["nodes"], counts["sub_uris"]))
    if counts.get("nodes") and counts["nodes"] < MIN_NODES_WARN:
        warnings.append("мало нод: %d (возможно, канал пуст/срезался)" % counts["nodes"])

    ok = not errors
    return ok, {"ok": ok, "errors": errors, "warnings": warnings,
                "counts": counts, "protocols": meta.get("protocols", {})}


def format_report(rep, verbose=True):
    lines = []
    lines.append("✅ Валидация пройдена" if rep["ok"] else "❌ Валидация НЕ пройдена")
    c = rep.get("counts", {})
    parts = ["%s=%d" % (k, c[k]) for k in
             ("nodes", "sub_uris", "node_files", "singbox_outbounds", "clash_proxies") if k in c]
    if parts:
        lines.append("  счётчики: " + ", ".join(parts))
    protos = rep.get("protocols") or {}
    if protos:
        lines.append("  протоколы: " + ", ".join(
            "%s=%d" % kv for kv in sorted(protos.items(), key=lambda x: -x[1])))
    for e in rep.get("errors", []):
        lines.append("  ✗ %s" % e)
    if verbose:
        for w in rep.get("warnings", []):
            lines.append("  ! %s" % w)
    return "\n".join(lines)


def validate_dir(path):
    """Проверить готовую папку out/ (для CLI/тестов)."""
    files = {}
    for root, _, names in os.walk(path):
        for nm in names:
            full = os.path.join(root, nm)
            rel = os.path.relpath(full, path).replace(os.sep, "/")
            with open(full, "r", encoding="utf-8") as f:
                files["out/" + rel] = f.read()
    return validate_outputs(files)


if __name__ == "__main__":
    import sys
    d = sys.argv[1] if len(sys.argv) > 1 else "out"
    ok, rep = validate_dir(d)
    print(format_report(rep, verbose=True))
    sys.exit(0 if ok else 2)
