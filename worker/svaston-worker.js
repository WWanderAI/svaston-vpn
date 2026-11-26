// Svaston VPN — Cloudflare Worker (бесплатно, без банковской карты)
// Загрузите этот файл в Cloudflare Dashboard -> Workers & Pages -> Create Worker

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const upgradeHeader = request.headers.get('Upgrade');

    // Проверка статуса воркера в браузере
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
      if (url.pathname === '/health') {
        return new Response(
          JSON.stringify({ status: 'ok', service: 'svaston-vpn-worker' }),
          { headers: { 'content-type': 'application/json' } }
        );
      }
      return new Response(
        'Svaston VPN Worker активен. Подключайтесь по WebSocket (WSS) через клиент.',
        { status: 200, headers: { 'content-type': 'text/plain; charset=utf-8' } }
      );
    }

    // Обработка WebSocket-туннеля
    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);

    server.accept();

    server.addEventListener('message', (event) => {
      // Эхо / прокси-обработка пакетов вашего протокола
      // Для полноценного TCP-туннелинга используйте `connect()` из `cloudflare:sockets`
      server.send(event.data);
    });

    server.addEventListener('close', () => {
      try {
        server.close();
      } catch {
        // ignore
      }
    });

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  },
};
