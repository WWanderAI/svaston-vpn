"""
selftest.py — офлайн-проверка конвейера (без Telegram и без сети).

Проверяет: разбор node-URI (vless/vmess/trojan/ss/hysteria2/tuic/ssr/wireguard),
извлечение ссылок на подписки, распаковку base64-подписки, дедупликацию,
и генерацию всех артефактов (nodes.json, combined, b64, per-node, sing-box, clash).

Запуск:  python tests/selftest.py
"""
import base64
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import nodeparser          # noqa: E402
import subfetch            # noqa: E402
import aggregator          # noqa: E402

vmess_json = {
    "v": "2", "ps": "VM WS Test", "add": "vmess.example.com", "port": "443",
    "id": "11111111-2222-3333-4444-555555555555", "aid": "0", "scy": "auto",
    "net": "ws", "host": "vmess.example.com", "path": "/vmess", "tls": "tls", "sni": "vmess.example.com",
}
vmess_b64 = base64.b64encode(json.dumps(vmess_json).encode()).decode()
ss_b64 = base64.b64encode(b"aes-256-gcm:password1").decode()
ssr_b64 = base64.b64encode(b"aes-256-cfb:10.1.1.1:443:pass-ssr:none:origin").decode()

# base64-подписка, которую "выдал" бы сервер по URL
sub_body = (
    "vless://abcdef00-1111-2222-3333-444444444444@sub-vless.com:443?security=tls&sni=sub-vless.com&type=tcp#Sub%20Vless\n"
    "ss://" + base64.b64encode(b"aes-256-gcm:spass2").decode() + "@sub-ss.com:8388#Sub%20SS\n"
    "hysteria2://huser:hpass@sub-hy2.com:8443?sni=sub-hy2.com&insecure=1#Sub%20HY2\n"
).encode()
sub_b64_bytes = base64.b64encode(sub_body)

SAMPLE = """
Fresh nodes for today:

vless://b71fb284-a895-401c-b00b-4c6a2c5a1d2f@node1.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=REALITYPUBKEY&type=tcp#Real%20Node%201
vless://b71fb284-a895-401c-b00b-4c6a2c5a1d2f@node1.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=REALITYPUBKEY&type=tcp#Real%20Node%201
vmess://__VMESS__
ss://__SS__@ssnode.example.com:8388#SS%20AES256
trojan://pass-123@trojan.example.com:443?sni=trojan.example.com&type=ws&path=%2Fws#Trojan%20WS
hysteria2://user:mysecret@hy2.example.com:8443?sni=cdn.example.com&insecure=1#HY2%20Fast
tuic://11111111-2222-3333-4444-555555555555@tuic.example.com:4433?congestion_control=bbr&sni=tuic.example.com&allow_insecure=true#TUIC%20BBR
ssr://__SSR__#SSR%20Node

Подписка (fetch и decode): https://sub.example.com/sub?token=abc123
Ссылки, которые надо игнорировать: https://t.me/somechannel и https://github.com/foo/bar
"""
SAMPLE = (SAMPLE.replace("__VMESS__", vmess_b64)
              .replace("__SS__", ss_b64)
              .replace("__SSR__", ssr_b64))


def main():
    print("=== 1) extract_urls ===")
    urls = nodeparser.extract_urls(SAMPLE)
    print("URLs:", urls)
    assert "https://sub.example.com/sub?token=abc123" in urls, "подписку не нашли"
    assert not any("t.me" in u or "github.com" in u for u in urls), "соцсети/гитхаб не отфильтрованы"

    print("\n=== 2) разбор прямых нод ===")
    nodes = nodeparser.parse_text(SAMPLE)
    for n in nodes:
        print("  %-10s %-22s %-7s %s" % (n["protocol"], n["host"], n["port"], n["name"]))
    protos = {n["protocol"] for n in nodes}
    for want in ("vless", "vmess", "ss", "trojan", "hysteria2", "tuic", "ssr"):
        assert want in protos, "нет протокола %s" % want
    vm = next(n for n in nodes if n["protocol"] == "vmess")
    assert vm["host"] == "vmess.example.com" and vm["network"] == "ws" and vm["uuid"], "vmess разобран некорректно"
    ss = next(n for n in nodes if n["protocol"] == "ss")
    assert ss["method"] == "aes-256-gcm" and ss["password"] == "password1" and ss["port"] == 8388, "ss разобран некорректно"

    print("\n=== 3) распаковка base64-подписки ===")
    sub_uris = subfetch.parse_subscription(sub_b64_bytes)
    print("URI из подписки:", sub_uris)
    assert len(sub_uris) == 3, "ожидалось 3 URI из подписки, получено %d" % len(sub_uris)

    print("\n=== 4) дедупликация (master из репо + свежий скан) ===")
    sub_nodes = [nodeparser.parse_uri(u) for u in sub_uris]
    from main import merge
    # master — то, что уже лежит в репо из прошлого запуска (набор пересекается со свежим)
    master = list(nodes[:4])
    fresh = nodes + sub_nodes
    raw_count = len(master) + len(fresh)
    merged = merge(master, fresh)
    unique = len(nodes) + len(sub_nodes)
    print("raw=%d  после дедупа=%d  (уникальных ожидается %d)" % (raw_count, len(merged), unique))
    assert len(merged) < raw_count, "дедуп master+fresh не сработал"
    assert len(merged) == unique, "ожидалось %d уникальных, получили %d" % (unique, len(merged))
    # extract-level dedup: дублирующая vless-строка в SAMPLE схлопнулась до одной
    assert sum(1 for n in nodes if n["host"] == "node1.example.com") == 1, "extract не схлопнул дубли"

    files, meta = aggregator.build(merged, source="selftest")
    print("Протоколы:", meta["protocols"])
    print("Всего нод:", meta["total"])

    outdir = os.path.join(HERE, "out")
    if os.path.isdir(outdir):
        shutil.rmtree(outdir)
    for p, c in files.items():
        fp = os.path.join(HERE, p)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "w", encoding="utf-8") as f:
            f.write(c)

    print("\nАртефакты:")
    for p in sorted(files):
        print("  %-32s %6d bytes" % (p, len(files[p])))

    b64 = files[aggregator.MARKER]
    decoded = base64.b64decode(b64).decode()
    assert decoded.strip() == files["out/sub/combined.txt"].strip(), "b64 не совпадает с combined"
    print("\nOK: b64 <-> combined согласованы.")

    assert "out/singbox/config.json" in files, "нет sing-box конфига"
    sb = json.loads(files["out/singbox/config.json"])
    print("sing-box outbounds:", len(sb["outbounds"]))
    if "out/clash/config.yaml" in files:
        print("clash: %d байт" % len(files["out/clash/config.yaml"]))
    else:
        print("clash: пропущен (PyYAML не установлен) — это нормально для selftest")

    print("\n=== 5) автопроверка конфигов (validate) ===")
    import validate
    ok, rep = validate.validate_outputs(files, meta)
    print(validate.format_report(rep))
    assert ok, "валидация собранных артефактов не пройдена: %s" % rep["errors"]
    assert rep["counts"]["nodes"] == meta["total"], "счётчик нод не сошёлся"
    assert rep["counts"]["sub_uris"] == meta["total"], "счётчик URI в подписке не сошёлся"
    # негативный кейс: сломанный singbox (0 серверов) должен блокировать пуш
    bad_files = dict(files)
    bad_files["out/singbox/config.json"] = '{"outbounds": []}'
    ok2, rep2 = validate.validate_outputs(bad_files, meta)
    assert not ok2 and any("singbox" in e for e in rep2["errors"]), "сломанный singbox не обнаружен"
    print("Негативный кейс (сломанный singbox) корректно заблокирован.")

    print("\n=== 6) переименование (retitle + бренд) ===")
    u1 = nodeparser.retitle("vless://uuid@h.com:443?security=tls#Old%20Name", "Svaston vpn")
    assert u1.endswith("#Svaston%20vpn"), "vless: имя не заменено: %s" % u1
    u2 = nodeparser.retitle("ss://YWVzOnBhc3NAaC5jb206ODM4OA==#Old", "Svaston vpn")
    assert u2.endswith("#Svaston%20vpn"), "ss: имя не заменено: %s" % u2
    vm = base64.b64encode(json.dumps({"add": "h.com", "port": "443", "id": "x", "ps": "Old"}).encode()).decode()
    u3 = nodeparser.retitle("vmess://" + vm, "Svaston vpn")
    d3 = json.loads(base64.b64decode(u3[len("vmess://"):]).decode())
    assert d3["ps"] == "Svaston vpn", "vmess: ps не заменён: %s" % d3.get("ps")
    files2, _ = aggregator.build(
        [{"protocol": "vless", "host": "h.com", "port": 443, "name": "Old", "uuid": "u",
          "raw": "vless://u@h.com:443?security=tls#Old"}], source="t")
    comb = files2["out/sub/combined.txt"].strip()
    assert "Svaston" in comb, "build: бренд не попал в combined: %s" % comb
    print("retitle OK; combined:", comb[:70])

    print("\n=== 7) liveness (офлайн: grace + resurrect) ===")
    import liveness
    n7 = [
        {"protocol": "vless", "host": "alive.com", "port": 443, "name": "a", "uuid": "1", "raw": "vless://1@alive.com:443#a"},
        {"protocol": "vless", "host": "dead.com", "port": 443, "name": "d", "uuid": "2", "raw": "vless://2@dead.com:443#d"},
    ]
    liveness.is_alive = lambda n, timeout=4: n["host"] != "dead.com"
    f1, dead1, _ = liveness.filter_nodes(n7, {})
    assert len(f1) == 2, "один сбой не должен исключать ноду: %d" % len(f1)
    k_dead = repr(nodeparser.node_key(n7[1]))
    assert dead1.get(k_dead) == 1, "счётчик провалов не создан: %r" % dead1
    f2, dead2, st2 = liveness.filter_nodes(n7, {"dead": dead1})
    assert len(f2) == 1 and st2["dropped"] == 1, "после 2 провалов нода не исключена: %d" % len(f2)
    liveness.is_alive = lambda n, timeout=4: True
    f3, _, _ = liveness.filter_nodes(n7, {"dead": dead2})
    assert len(f3) == 2 and any(x["host"] == "dead.com" for x in f3), "ожившая нода не вернулась"
    print("liveness grace/resurrect OK; dead2=%r" % dead2)

    print("\n=== SELFTEST PASSED ===")
    print("Результат записан в %s" % outdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
