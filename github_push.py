"""
github_push.py — пушит сгенерированный каталог out/ в GitHub-репо через Git Trees API.

Плюсы подхода: один коммит на запуск, удаляем только то, что устарело,
и дешёвый guard (сравниваем бейз64-подписку) — если набор нод не изменился,
API не трогаем вовсе (экономим rate limit).

Токен: сначала смотрим GH_TOKEN (PAT для другого репо), потом GITHUB_TOKEN
(автотокен в Actions для текущего репо).
"""
import base64
import os

API = "https://api.github.com"


def make_pusher():
    import requests  # noqa: F401 (проверяем наличие)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("Нет токена: задай GH_TOKEN или GITHUB_TOKEN")
    return GitHubPusher(token)


class GitHubPusher:
    def __init__(self, token):
        self.token = token
        self.headers = {
            "Authorization": "Bearer %s" % token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "vpn-aggregator",
        }
        self.owner = os.environ.get("GH_OWNER")
        self.repo = os.environ.get("GH_REPO_NAME")
        self.branch = os.environ.get("GH_BRANCH")

    def _api(self, method, path, **kw):
        import requests
        import time
        last = None
        for attempt in range(4):
            r = requests.request(method, API + path, headers=self.headers, timeout=60, **kw)
            if r.status_code == 403 and "secondary rate limit" in r.text:
                wait = 20 * (attempt + 1)
                print("GitHub secondary rate limit — пауза %ds (повтор %d/3)" % (wait, attempt + 1))
                time.sleep(wait)
                last = r
                continue
            if r.status_code >= 400:
                raise RuntimeError("GitHub %s %s -> %s: %s" % (method, path, r.status_code, r.text[:500]))
            return r.json() if r.text else {}
        raise RuntimeError("GitHub %s %s: secondary rate limit, повторы исчерпаны" % (method, path))

    @staticmethod
    def _blob_sha(content):
        """Локальный git-blob SHA: SHA1('blob <size>\0' + bytes). Совпадает с GitHub."""
        import hashlib
        data = content.encode("utf-8") if isinstance(content, str) else content
        return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()

    def _existing_out_map(self, root_tree_sha):
        """Путь (out/...) -> blob sha из текущего дерева — один рекурсивный запрос."""
        d = self._api("GET", self._r("/git/trees/%s" % root_tree_sha) + "?recursive=1")
        if d.get("truncated"):
            raise RuntimeError("рекурсивное дерево обрезано (truncated)")
        return {e["path"]: e["sha"] for e in d.get("tree", [])
                if e.get("type") == "blob" and e.get("path", "").startswith("out/")}

    def _r(self, path):
        return "/repos/%s/%s%s" % (self.owner, self.repo, path)

    def resolve(self):
        if not (self.owner and self.repo):
            full = os.environ.get("GH_REPO") or os.environ.get("GITHUB_REPOSITORY")
            if not full:
                raise RuntimeError("Не указан репо: GH_REPO=owner/name")
            self.owner, self.repo = full.split("/", 1)
        if not self.branch:
            self.branch = os.environ.get("GITHUB_REF_NAME")
        if not self.branch:
            info = self._api("GET", self._r(""))
            self.branch = info.get("default_branch", "main")

    def read_file(self, path):
        try:
            d = self._api("GET", self._r("/contents/%s" % path) + "?ref=%s" % self.branch)
        except Exception:
            return None
        if isinstance(d, dict) and d.get("content"):
            return base64.b64decode(d["content"]).decode("utf-8", "replace")
        return None

    def needs_push(self, files, marker):
        cur = self.read_file(marker)
        return cur != files.get(marker)

    def do_push(self, files, message):
        # Локально считаем git-blob SHA каждого файла, чтобы переиспользовать
        # уже лежащие в репо блобы и грузить в API только изменившиеся.
        local_sha = {p: self._blob_sha(c) for p, c in files.items()}

        last_err = None
        for _ in range(3):
            head = self._api("GET", self._r("/git/ref/heads/%s" % self.branch))
            head_sha = head["object"]["sha"]
            commit = self._api("GET", self._r("/git/commits/%s" % head_sha))
            root_tree_sha = commit["tree"]["sha"]
            root = self._api("GET", self._r("/git/trees/%s" % root_tree_sha))["tree"]
            existing = self._existing_out_map(root_tree_sha)

            blob_sha, created = {}, 0
            for p, c in files.items():
                if existing.get(p) == local_sha[p]:
                    blob_sha[p] = existing[p]          # неизменено — без POST
                else:
                    blob_sha[p] = self._api("POST", self._r("/git/blobs"),
                                            json={"content": c, "encoding": "utf-8"})["sha"]
                    created += 1

            out_entries = [{"path": p[len("out/"):], "mode": "100644", "type": "blob", "sha": blob_sha[p]}
                           for p in files]
            out_tree = self._api("POST", self._r("/git/trees"), json={"tree": out_entries})["sha"]

            new_root, replaced = [], False
            for e in root:
                if e["path"] == "out":
                    new_root.append({"path": "out", "type": "tree", "mode": "040000", "sha": out_tree})
                    replaced = True
                else:
                    item = {"path": e["path"], "type": e["type"], "sha": e["sha"]}
                    item["mode"] = e.get("mode") or ("040000" if e.get("type") == "tree" else "100644")
                    new_root.append(item)
            if not replaced:
                new_root.append({"path": "out", "type": "tree", "mode": "040000", "sha": out_tree})

            new_tree = self._api("POST", self._r("/git/trees"), json={"tree": new_root})["sha"]
            new_commit = self._api("POST", self._r("/git/commits"),
                                   json={"message": message, "tree": new_tree, "parents": [head_sha]})["sha"]
            try:
                self._api("PATCH", self._r("/git/refs/heads/%s" % self.branch), json={"sha": new_commit, "force": False})
                print("do_push: новых блобов %d из %d (остальные переиспользованы)" % (created, len(files)))
                return new_commit
            except RuntimeError as e:
                if "not a fast forward" in str(e):
                    last_err = e  # head сменился под нами — перечитываем и повторяем
                    continue
                raise
        raise last_err if last_err else RuntimeError("do_push: исчерпаны повторы")
