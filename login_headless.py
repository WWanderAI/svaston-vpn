"""
login_headless.py — разовый вход без интерактивного терминала (2 фазы).

Требует переменные окружения TG_API_ID и TG_API_HASH (и опц. TG_CHANNEL).

  Фаза 1 — отправить код:
      python login_headless.py send "+79991234567"
      -> создаёт session.session, шлёт код в Telegram, печатает CODE_SENT

  Фаза 2 — подтвердить (код из Telegram + пароль 2FA, если включён):
      python login_headless.py confirm "+79991234567" 12345 [пароль2FA]
      -> завершает вход, проверяет доступ к каналу, печатает BASE64=<...>

BASE64 из фазы 2 = значение секрета TG_SESSION в GitHub Actions.
"""
import base64
import os
import sys

API_ID = os.environ.get("TG_API_ID")
API_HASH = os.environ.get("TG_API_HASH")
SESSION = os.environ.get("TG_SESSION_FILE", "session.session")
CHANNEL = os.environ.get("TG_CHANNEL", "").strip()


def _client():
    from telethon import TelegramClient
    if not (API_ID and API_HASH):
        raise SystemExit("Задай TG_API_ID и TG_API_HASH")
    return TelegramClient(SESSION, int(API_ID), API_HASH)


def _verify(client):
    me = client.get_me()
    print("Войдено: %s @%s (id %s)" % (me.first_name, me.username, me.id))
    if CHANNEL:
        ent = client.get_entity(CHANNEL)
        n = sum(1 for _ in client.iter_messages(ent, limit=3))
        print("Канал OK: %s (id %s), прочитано %s сообщений" % (getattr(ent, "title", None), ent.id, n))
    else:
        print("Канал не указан (TG_CHANNEL пуст) — пропущена проверка.")


def send(phone):
    client = _client()
    with client:
        client.send_code_request(phone)
    print("CODE_SENT")
    print("Код отправлен в Telegram на %s." % phone)


def confirm(phone, code, password):
    client = _client()
    with client:
        client.sign_in(phone, code=code, password=password or None)
        _verify(client)
    with open(SESSION, "rb") as f:
        data = f.read()
    print("SESSION_OK")
    print("SESSION_FILE=%s (%d байт)" % (os.path.abspath(SESSION), len(data)))
    print("BASE64=" + base64.b64encode(data).decode())


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    cmd, phone = sys.argv[1], sys.argv[2]
    if cmd == "send":
        send(phone)
    elif cmd == "confirm":
        if len(sys.argv) < 4:
            print("Нужен код: python login_headless.py confirm <phone> <code> [password]")
            sys.exit(1)
        confirm(phone, sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else "")
    else:
        print("Неизвестная команда:", cmd)
        sys.exit(1)


if __name__ == "__main__":
    main()
