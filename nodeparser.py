"""
nodeparser.py — достаёт node-URI из текста и нормализует их в структуры.

Поддерживаемые схемы: vless, vmess, trojan, ss, ssr, hysteria2/hy2/hy,
tuic, shadowtls, wireguard, ssh, amnezia, socks5.
Главная ценность — сохранение исходного raw-URI (его импортируют клиенты),
плюс извлечённые поля (host/port/credentials/сеть/sni) для дедупликации
и генерации sing-box / clash конфигов.
"""
import base64
import json
import re
import urllib.parse as up

SCHEMES = [
    "vless", "vmess", "trojan", "shadowtls", "hysteria2", "hy2", "hy",
    "tuic", "ssr", "ss", "wireguard", "ssh", "amnezia", "socks5",
]
_SCHEMES = sorted(SCHEMES, key=len, reverse=True)
URI_RE = re.compile(r"(?i)\b(" + "|".join(_SCHEMES) + r")://[^\s\"'<>\n]+")

_TRAIL = ")\"'.,;:!?"
LEAD = "(\"'`"


def _b64decode(s, urlsafe=False):
    if not s:
        return None
    s = s.strip()
    pad = s + "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(pad) if urlsafe else base64.b64decode(pad)
    except Exception:
        return None


def _clean(uri):
    return uri.strip().strip(LEAD).rstrip(_TRAIL).strip()


def _int(x):
    try:
        return int(str(x).strip())
    except Exception:
        return 0


def split_hostport(s):
    s = (s or "").strip()
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        return host, rest.lstrip(":") or 0
    if ":" in s:
        host, port = s.rsplit(":", 1)
        return host, (port or 0)
    return s, 0


def make_node(protocol, host, port, name, raw, **kw):
    host = (host or "").strip().strip("[]")
    port = _int(port)
    name = (name or "").strip() or "%s %s:%s" % (protocol, host or "?", port or "?")
    n = {"protocol": protocol, "host": host, "port": port, "name": name, "raw": raw}
    n.update(kw)
    return n


def extract_uris(text):
    if not text:
        return []
    out, seen = [], set()
    for m in URI_RE.finditer(text):
        u = _clean(m.group(0))
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


HTTP_RE = re.compile(r"(?i)\bhttps?://[^\s\"'<>\n]+")
EXCLUDE_HOSTS = (
    "t.me", "telegram.me", "telegram.org", "t.co", "youtu.be", "youtube.com",
    "google.com", "googleusercontent.com", "twitter.com", "x.com", "vk.com",
    "ok.ru", "medium.com", "reddit.com", "facebook.com", "instagram.com",
    "github.com", "gitlab.com",  # repo pages — не подписки (raw.githubusercontent.com остаётся)
)


def extract_urls(text):
    if not text:
        return []
    out, seen = [], set()
    for m in HTTP_RE.finditer(text):
        u = _clean(m.group(0)).rstrip(".,;:!?)'\"")
        try:
            host = (up.urlsplit(u).hostname or "").lower()
        except Exception:
            continue
        if not host or "." not in host:
            continue
        if any(host == e or host.endswith("." + e) for e in EXCLUDE_HOSTS):
            continue
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


# --------------------------------------------------------------------- parsers
def parse_vless(uri):
    body = uri[len("vless://"):].strip()
    name = ""
    if "#" in body:
        body, name = body.rsplit("#", 1)
        name = up.unquote(name)
    cred, rest = (body.rsplit("@", 1) if "@" in body else ("", body))
    hostport, q = (rest.split("?", 1) if "?" in rest else (rest, ""))
    params = dict(up.parse_qsl(q, keep_blank_values=True))
    host, port = split_hostport(hostport)
    return make_node(
        "vless", host, port, name, uri, uuid=cred,
        network=params.get("type", "tcp"), security=params.get("security", "none"),
        sni=params.get("sni") or params.get("peer") or "", host_header=params.get("host", ""),
        path=params.get("path", ""), service_name=params.get("serviceName", ""),
        fingerprint=params.get("fp", ""), pbk=params.get("pbk", ""),
        sid=params.get("sid", ""), spx=params.get("spx", ""),
        allow_insecure=params.get("allowInsecure", "0") == "1",
        flow=params.get("flow", ""), encryption=params.get("encryption", "none"),
    )


def parse_vmess(uri):
    body = uri[len("vmess://"):].strip()
    d = {}
    data = _b64decode(body)
    if data:
        try:
            d = json.loads(data.decode("utf-8", "replace"))
        except Exception:
            d = {}
    name = d.get("ps") or d.get("name") or ""
    host = d.get("add") or d.get("addr") or ""
    port = d.get("port") or 0
    alpn = d.get("alpn", [])
    alpn = ",".join(alpn) if isinstance(alpn, list) else (alpn or "")
    return make_node(
        "vmess", host, port, name, uri, uuid=d.get("id"), aid=_int(d.get("aid", 0)),
        cipher=d.get("scy", "auto"), network=d.get("net", "tcp"),
        type=d.get("type", "none"), host_header=d.get("host", ""),
        path=d.get("path", ""), tls=bool(d.get("tls")), sni=d.get("sni") or d.get("host", ""),
        alpn=alpn, fingerprint=d.get("fp", ""),
    )


def parse_ss(uri):
    body = uri[len("ss://"):].strip()
    name = ""
    if "#" in body:
        body, name = body.rsplit("#", 1)
        name = up.unquote(name)
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        host, port = split_hostport(hostport)
        dec = _b64decode(userinfo)
        if dec and ":" in dec.decode("utf-8", "replace"):
            method, password = dec.decode("utf-8", "replace").split(":", 1)
            return make_node("ss", host, port, name, uri, method=method, password=password)
        if ":" in userinfo and not re.match(r"^[A-Za-z0-9+/=_-]+$", userinfo):
            method, password = userinfo.split(":", 1)
            return make_node("ss", host, port, name, uri, method=method, password=password)
    dec = _b64decode(body) or _b64decode(body, urlsafe=True)
    if dec:
        mp = dec.decode("utf-8", "replace")
        if "@" in mp and ":" in mp:
            userinfo, hostport = mp.rsplit("@", 1)
            host, port = split_hostport(hostport)
            method, password = userinfo.split(":", 1)
            return make_node("ss", host, port, name, uri, method=method, password=password)
    return make_node("ss", "", 0, name, uri)


def parse_ssr(uri):
    body = uri[len("ssr://"):].strip()
    name = ""
    if "#" in body:
        body, name = body.rsplit("#", 1)
        name = up.unquote(name)
    dec = _b64decode(body, urlsafe=True) or _b64decode(body)
    fields = dec.decode("utf-8", "replace").split(":") if dec else []
    if len(fields) >= 6:
        method, host, port, password, obfs, plugin = fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]
        return make_node("ssr", host, port, name, uri, method=method, password=password,
                         obfs=obfs, plugin=plugin, extra=":".join(fields[6:]))
    return make_node("ssr", "", 0, name, uri)


def _split_query(rest):
    if "?" in rest:
        head, q = rest.split("?", 1)
        return head, dict(up.parse_qsl(q, keep_blank_values=True))
    return rest, {}


def parse_trojan(uri):
    body = uri[len("trojan://"):].strip()
    name = ""
    if "#" in body:
        body, name = body.rsplit("#", 1)
        name = up.unquote(name)
    cred, rest = (body.rsplit("@", 1) if "@" in body else ("", body))
    hostport, params = _split_query(rest)
    host, port = split_hostport(hostport)
    return make_node(
        "trojan", host, port, name, uri, password=cred,
        network=params.get("type", "tcp"), sni=params.get("sni", ""),
        host_header=params.get("host", ""), path=params.get("path", ""),
        alpn=params.get("alpn", ""), fingerprint=params.get("fp", ""),
        allow_insecure=params.get("allowInsecure", "0") == "1",
    )


def parse_hysteria(uri, proto):
    body = uri.split("://", 1)[1].strip()
    name = ""
    if "#" in body:
        body, name = body.rsplit("#", 1)
        name = up.unquote(name)
    cred, rest = (body.rsplit("@", 1) if "@" in body else ("", body))
    hostport, params = _split_query(rest)
    host, port = split_hostport(hostport)
    user, _, pw = cred.partition(":")
    return make_node(
        proto, host, port, name, uri, user=user, password=pw,
        sni=params.get("sni", ""), insecure=params.get("insecure", "0") in ("1", "true"),
        pin=params.get("pinSHA256", ""),
    )


def parse_tuic(uri):
    body = uri.split("://", 1)[1].strip()
    name = ""
    if "#" in body:
        body, name = body.rsplit("#", 1)
        name = up.unquote(name)
    cred, rest = (body.rsplit("@", 1) if "@" in body else ("", body))
    hostport, params = _split_query(rest)
    host, port = split_hostport(hostport)
    return make_node(
        "tuic", host, port, name, uri, uuid=cred,
        congestion=params.get("congestion_control", "bbr"),
        allow_insecure=params.get("allow_insecure", "false") in ("true", "1"),
        sni=params.get("sni", ""),
    )


def parse_wireguard(uri):
    body = uri.split("://", 1)[1].strip()
    name = ""
    if "#" in body:
        body, name = body.rsplit("#", 1)
        name = up.unquote(name)
    if "=" in body and not re.match(r"^[A-Za-z0-9+/=_-]+$", body):
        q = body.split("?", 1)[1] if "?" in body else body
        info = dict(up.parse_qsl(q, keep_blank_values=True))
        ep = info.get("endpoint", "")
        host, port = split_hostport(ep)
        return make_node("wireguard", host, port, name, uri, endpoint=ep,
                         private_key=info.get("privatekey", ""), public_key=info.get("publickey", ""),
                         ip=info.get("ip", ""), keepalive=info.get("keepalive", ""),
                         mtu=info.get("mtu", ""))
    dec = _b64decode(body) or _b64decode(body, urlsafe=True)
    if dec:
        return make_node("wireguard", "", 0, name, uri, config=dec.decode("utf-8", "replace"))
    return make_node("wireguard", "", 0, name, uri)


def parse_ssh(uri):
    body = uri.split("://", 1)[1].strip()
    name = ""
    if "#" in body:
        body, name = body.rsplit("#", 1)
        name = up.unquote(name)
    cred, hostport = (body.rsplit("@", 1) if "@" in body else ("", body))
    host, port = split_hostport(hostport)
    user, _, pw = cred.partition(":")
    return make_node("ssh", host, port, name, uri, user=user, password=pw)


def parse_generic(uri, protocol, warn=None):
    m = re.match(r"(?i)^([\w-]+)://", uri)
    scheme = m.group(1).lower() if m else (protocol or "unknown")
    body = uri.split("://", 1)[1] if "://" in uri else ""
    name = ""
    if "#" in body:
        body, name = body.rsplit("#", 1)
        name = up.unquote(name)
    cred, rest = (body.rsplit("@", 1) if "@" in body else ("", body))
    host, port = split_hostport(rest.split("?")[0])
    return make_node(scheme, host, port, name, uri, unknown=True, warn=warn or "")


def parse_uri(uri):
    m = re.match(r"(?i)^([\w-]+)://", uri)
    scheme = m.group(1).lower() if m else ""
    try:
        if scheme == "vless":
            return parse_vless(uri)
        if scheme == "vmess":
            return parse_vmess(uri)
        if scheme == "trojan":
            return parse_trojan(uri)
        if scheme == "ss":
            return parse_ss(uri)
        if scheme == "ssr":
            return parse_ssr(uri)
        if scheme in ("hysteria2", "hy2"):
            return parse_hysteria(uri, "hysteria2")
        if scheme == "hy":
            return parse_hysteria(uri, "hy")
        if scheme == "tuic":
            return parse_tuic(uri)
        if scheme == "wireguard":
            return parse_wireguard(uri)
        if scheme == "ssh":
            return parse_ssh(uri)
    except Exception as e:
        return parse_generic(uri, scheme, warn=str(e))
    return parse_generic(uri, scheme)


def parse_text(text):
    return [parse_uri(u) for u in extract_uris(text)]


def retitle(uri, name):
    """Меняет имя узла в raw-URI: фрагмент '#…' для большинства схем и поле
    'ps' (в b64-JSON) для vmess. Если имя негде поменять — возвращает как есть."""
    if not uri or name is None:
        return uri
    name = str(name)
    if uri.lower().startswith("vmess://"):
        body = uri[len("vmess://"):].strip()
        raw = _b64decode(body)
        if not raw:
            return uri
        try:
            d = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            return uri
        d["ps"] = name
        return "vmess://" + base64.b64encode(json.dumps(d).encode()).decode()
    enc = up.quote(name, safe="")
    head = uri.rsplit("#", 1)[0] if "#" in uri else uri
    return head + "#" + enc


def node_key(n):
    p = n.get("protocol")
    if p == "ss":
        cred = "%s|%s" % (n.get("method", ""), n.get("password", ""))
    elif p == "ssr":
        cred = "%s|%s|%s" % (n.get("password", ""), n.get("obfs", ""), n.get("plugin", ""))
    else:
        cred = n.get("uuid") or n.get("password") or n.get("private_key") or n.get("config") or ""
    extra = n.get("network") or n.get("path") or n.get("sni") or n.get("aid") or n.get("aid") or ""
    return (p, str(n.get("host", "")), str(n.get("port", "")), str(cred), str(extra))
