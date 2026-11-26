import { useEffect, useMemo, useState } from 'react'
import {
  Check,
  Copy,
  Download,
  Globe,
  KeyRound,
  QrCode,
  RefreshCw,
  Server,
  Shield,
  Sliders,
  Terminal,
  X,
} from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'

function randomHex(len = 16) {
  const bytes = new Uint8Array(len)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

function randomUuid() {
  if (crypto.randomUUID) return crypto.randomUUID()
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0
    const v = c === 'x' ? r : (r & 0x3) | 0x8
    return v.toString(16)
  })
}

export default function App() {
  const [tab, setTab] = useState('nodes')
  const [nodes, setNodes] = useState([])
  const [meta, setMeta] = useState(null)
  const [loading, setLoading] = useState(true)
  const [copiedId, setCopiedId] = useState(null)
  const [qrModal, setQrModal] = useState(null)

  // Custom protocol builder state
  const [proto, setProto] = useState({
    name: 'Svaston-Worker-v1',
    scheme: 'svaston',
    host: 'gentle-scene-479e.noob15526.workers.dev',
    port: '443',
    transport: 'ws-cdn',
    encryption: 'chacha20-poly1305',
    obfuscation: 'tls13-utls-chrome',
    sni: 'gentle-scene-479e.noob15526.workers.dev',
    mtu: '1380',
    keepalive: '25',
    uuid: randomUuid(),
    psk: randomHex(16),
    magicHeader: 'SVST01',
  })

  useEffect(() => {
    Promise.all([
      fetch('/data/nodes.json').then((r) => (r.ok ? r.json() : [])),
      fetch('/data/meta.json').then((r) => (r.ok ? r.json() : null)),
    ])
      .then(([n, m]) => {
        setNodes(Array.isArray(n) ? n : [])
        setMeta(m)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const copyText = (text, id) => {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 1800)
  }

  const origin = typeof window !== 'undefined' ? window.location.origin : ''
  const subB64Url = `${origin}/data/b64.txt`
  const subRawUrl = `${origin}/data/combined.txt`

  const customUri = useMemo(() => {
    const params = new URLSearchParams({
      transport: proto.transport,
      enc: proto.encryption,
      obfs: proto.obfuscation,
      sni: proto.sni,
      mtu: proto.mtu,
      ka: proto.keepalive,
      magic: proto.magicHeader,
      psk: proto.psk,
    })
    return `${proto.scheme}://${proto.uuid}@${proto.host}:${proto.port}?${params.toString()}#${encodeURIComponent(proto.name)}`
  }, [proto])

  const clientConfig = useMemo(
    () =>
      JSON.stringify(
        {
          protocol: proto.scheme,
          profile: proto.name,
          server: proto.host,
          port: Number(proto.port) || 443,
          auth: {
            uuid: proto.uuid,
            psk: proto.psk,
          },
          transport: {
            type: proto.transport,
            obfuscation: proto.obfuscation,
            sni: proto.sni,
            magic_header: proto.magicHeader,
            mtu: Number(proto.mtu) || 1380,
            keepalive_sec: Number(proto.keepalive) || 25,
          },
          crypto: {
            cipher: proto.encryption,
          },
          routing: {
            dns: ['1.1.1.1', '8.8.8.8'],
            bypass_lan: true,
          },
        },
        null,
        2
      ),
    [proto]
  )

  const serverScript = useMemo(() => {
    return `#!/usr/bin/env bash
set -euo pipefail

# Автоматическое развёртывание Svaston VPN (${proto.name})
# Подходит для любого бесплатного VPS (Ubuntu / Debian)

mkdir -p /opt/svaston-vpn && cd /opt/svaston-vpn

cat > config.json <<'EOF'
{
  "listen": "0.0.0.0:${proto.port}",
  "protocol": "${proto.scheme}",
  "transport": "${proto.transport}",
  "encryption": "${proto.encryption}",
  "obfuscation": "${proto.obfuscation}",
  "sni": "${proto.sni}",
  "magic_header": "${proto.magicHeader}",
  "mtu": ${Number(proto.mtu) || 1380},
  "clients": [
    {
      "uuid": "${proto.uuid}",
      "psk": "${proto.psk}"
    }
  ]
}
EOF

echo "Конфиг сохранён в /opt/svaston-vpn/config.json"
echo "URI для подключения:"
echo "${customUri}"
`
  }, [proto, customUri])

  const downloadFile = (filename, content) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="container">
      <header className="header">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={24} />
          </div>
          <div>
            <h1>Svaston VPN</h1>
            <p>Полностью бесплатный VPN и конструктор своего протокола</p>
          </div>
        </div>

        <nav className="tabs">
          <button
            className={`tab-btn ${tab === 'nodes' ? 'active' : ''}`}
            onClick={() => setTab('nodes')}
          >
            <Globe size={16} /> Бесплатный VPN
          </button>
          <button
            className={`tab-btn ${tab === 'builder' ? 'active' : ''}`}
            onClick={() => setTab('builder')}
          >
            <Sliders size={16} /> Свой протокол
          </button>
          <button
            className={`tab-btn ${tab === 'server' ? 'active' : ''}`}
            onClick={() => setTab('server')}
          >
            <Server size={16} /> Создать сервер
          </button>
        </nav>
      </header>

      {tab === 'nodes' && (
        <>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-label">Доступно узлов</div>
              <div className="stat-value" style={{ color: 'var(--accent)' }}>
                {nodes.length}
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Статус подписки</div>
              <div className="stat-value">Бесплатно 24/7</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Источник</div>
              <div className="stat-value" style={{ fontSize: '1.1rem' }}>
                {meta?.source || 'manual_nodes.txt'}
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-title">
              <KeyRound size={18} style={{ color: 'var(--accent)' }} />
              Ссылки на подписку (для Hiddify, v2rayNG, Nekobox, Streisand)
            </div>
            <div className="sub-box">
              <span className="sub-url">{subB64Url}</span>
              <button
                className="btn btn-primary"
                onClick={() => copyText(subB64Url, 'sub-b64')}
              >
                {copiedId === 'sub-b64' ? <Check size={15} /> : <Copy size={15} />}
                {copiedId === 'sub-b64' ? 'Скопировано' : 'Base64 подписка'}
              </button>
              <button
                className="btn"
                onClick={() => setQrModal({ title: 'Base64 подписка', value: subB64Url })}
              >
                <QrCode size={15} /> QR
              </button>
            </div>
            <div className="sub-box">
              <span className="sub-url">{subRawUrl}</span>
              <button className="btn" onClick={() => copyText(subRawUrl, 'sub-raw')}>
                {copiedId === 'sub-raw' ? <Check size={15} /> : <Copy size={15} />}
                {copiedId === 'sub-raw' ? 'Скопировано' : 'Список URI'}
              </button>
            </div>
          </div>

          <div className="card">
            <div className="card-title">
              <Server size={18} style={{ color: 'var(--cyan)' }} />
              Список бесплатных серверов
            </div>
            {loading ? (
              <p style={{ color: 'var(--text-muted)' }}>Загрузка узлов...</p>
            ) : nodes.length === 0 ? (
              <p style={{ color: 'var(--text-muted)' }}>
                Узлы не найдены. Запустите <code>python main.py</code> для генерации.
              </p>
            ) : (
              <div className="node-list">
                {nodes.map((node, idx) => (
                  <div className="node-item" key={idx}>
                    <div className="node-info">
                      <div className="node-name">
                        <span className="badge">{node.scheme || 'vpn'}</span>
                        <span className="badge badge-ok">FREE</span>
                        <span>{node.name || `${node.host}:${node.port}`}</span>
                      </div>
                      <div className="node-meta">
                        {node.host}:{node.port}
                      </div>
                    </div>
                    <div className="node-actions">
                      <button
                        className="btn"
                        onClick={() => copyText(node.raw, `node-${idx}`)}
                      >
                        {copiedId === `node-${idx}` ? (
                          <Check size={15} />
                        ) : (
                          <Copy size={15} />
                        )}
                        {copiedId === `node-${idx}` ? 'Скопировано' : 'Копировать URI'}
                      </button>
                      <button
                        className="btn"
                        onClick={() =>
                          setQrModal({
                            title: node.name || `${node.host}:${node.port}`,
                            value: node.raw,
                          })
                        }
                      >
                        <QrCode size={15} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}

      {tab === 'builder' && (
        <div className="grid-2">
          <div className="card">
            <div className="card-title">
              <Sliders size={18} style={{ color: 'var(--accent)' }} />
              Конструктор своего протокола
            </div>

            <div className="form-group">
              <label>Название профиля</label>
              <input
                className="form-control"
                value={proto.name}
                onChange={(e) => setProto({ ...proto, name: e.target.value })}
              />
            </div>

            <div className="grid-2" style={{ gap: 12 }}>
              <div className="form-group">
                <label>Схема протокола</label>
                <input
                  className="form-control"
                  value={proto.scheme}
                  onChange={(e) => setProto({ ...proto, scheme: e.target.value })}
                />
              </div>
              <div className="form-group">
                <label>Порт</label>
                <input
                  className="form-control"
                  value={proto.port}
                  onChange={(e) => setProto({ ...proto, port: e.target.value })}
                />
              </div>
            </div>

            <div className="form-group">
              <label>Сервер (IP или домен)</label>
              <input
                className="form-control"
                value={proto.host}
                onChange={(e) => setProto({ ...proto, host: e.target.value })}
              />
            </div>

            <div className="form-group">
              <label>Транспорт</label>
              <select
                className="form-control"
                value={proto.transport}
                onChange={(e) => setProto({ ...proto, transport: e.target.value })}
              >
                <option value="quic-obfs">QUIC + Custom Obfuscation (UDP)</option>
                <option value="tcp-reality">TCP + Reality</option>
                <option value="ws-cdn">WebSocket (через Cloudflare CDN)</option>
                <option value="grpc-tls">gRPC + TLS 1.3</option>
                <option value="raw-udp-xor">Raw UDP + XOR Magic Header</option>
              </select>
            </div>

            <div className="form-group">
              <label>Шифрование</label>
              <select
                className="form-control"
                value={proto.encryption}
                onChange={(e) => setProto({ ...proto, encryption: e.target.value })}
              >
                <option value="chacha20-poly1305">ChaCha20-Poly1305 (быстрое для мобильных)</option>
                <option value="aes-256-gcm">AES-256-GCM (аппаратное ускорение)</option>
                <option value="xchacha20-poly1305">XChaCha20-Poly1305</option>
              </select>
            </div>

            <div className="grid-2" style={{ gap: 12 }}>
              <div className="form-group">
                <label>SNI (маскировка домена)</label>
                <input
                  className="form-control"
                  value={proto.sni}
                  onChange={(e) => setProto({ ...proto, sni: e.target.value })}
                />
              </div>
              <div className="form-group">
                <label>Magic Header (сигнатура)</label>
                <input
                  className="form-control"
                  value={proto.magicHeader}
                  onChange={(e) => setProto({ ...proto, magicHeader: e.target.value })}
                />
              </div>
            </div>

            <button
              className="btn"
              onClick={() =>
                setProto({
                  ...proto,
                  uuid: randomUuid(),
                  psk: randomHex(16),
                })
              }
            >
              <RefreshCw size={15} /> Сгенерировать новые ключи
            </button>
          </div>

          <div>
            <div className="card">
              <div className="card-title">
                <QrCode size={18} style={{ color: 'var(--cyan)' }} />
                URI вашего протокола
              </div>
              <div className="code-block" style={{ marginBottom: 12 }}>
                {customUri}
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button
                  className="btn btn-primary"
                  onClick={() => copyText(customUri, 'custom-uri')}
                >
                  {copiedId === 'custom-uri' ? <Check size={15} /> : <Copy size={15} />}
                  {copiedId === 'custom-uri' ? 'Скопировано' : 'Копировать URI'}
                </button>
                <button
                  className="btn"
                  onClick={() => setQrModal({ title: proto.name, value: customUri })}
                >
                  <QrCode size={15} /> Показать QR
                </button>
              </div>
            </div>

            <div className="card">
              <div className="card-title">
                <Terminal size={18} style={{ color: 'var(--accent)' }} />
                Клиентский конфиг (JSON)
              </div>
              <div className="code-block" style={{ marginBottom: 12 }}>
                {clientConfig}
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button
                  className="btn"
                  onClick={() => copyText(clientConfig, 'client-json')}
                >
                  {copiedId === 'client-json' ? <Check size={15} /> : <Copy size={15} />}
                  Копировать JSON
                </button>
                <button
                  className="btn"
                  onClick={() => downloadFile('svaston-client.json', clientConfig)}
                >
                  <Download size={15} /> Скачать .json
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {tab === 'server' && (
        <div className="grid-2">
          <div className="card">
            <div className="card-title">
              <Server size={18} style={{ color: 'var(--accent)' }} />
              Как создать свой бесплатный VPN-сервер
            </div>
            <div className="guide-step">
              <div className="step-num">1</div>
              <div>
                <strong>Выберите бесплатный хостинг БЕЗ банковской карты</strong>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>
                  • <strong>Cloudflare Workers</strong> — бесплатно 100 000 запросов/день, карта не нужна (отлично для WebSocket/VLESS-прокси).<br />
                  • <strong>Hugging Face Spaces (Docker)</strong> — 2 vCPU / 16 GB RAM бесплатно без карты.<br />
                  • <strong>GitHub Codespaces</strong> — 60 часов/месяц бесплатно без карты для личного туннеля.
                </p>
              </div>
            </div>
            <div className="guide-step">
              <div className="step-num">2</div>
              <div>
                <strong>Настройте свой протокол во вкладке «Свой протокол»</strong>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>
                  Укажите IP вашего сервера, выберите транспорт, шифрование и сгенерируйте
                  уникальные ключи.
                </p>
              </div>
            </div>
            <div className="guide-step">
              <div className="step-num">3</div>
              <div>
                <strong>Запустите скрипт установки на сервере</strong>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>
                  Скопируйте скрипт справа и выполните его на вашем Ubuntu/Debian сервере.
                </p>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-title">
              <Terminal size={18} style={{ color: 'var(--cyan)' }} />
              Скрипт развёртывания (install-svaston-vpn.sh)
            </div>
            <div className="code-block" style={{ marginBottom: 12 }}>
              {serverScript}
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <button
                className="btn btn-primary"
                onClick={() => copyText(serverScript, 'server-sh')}
              >
                {copiedId === 'server-sh' ? <Check size={15} /> : <Copy size={15} />}
                {copiedId === 'server-sh' ? 'Скопировано' : 'Копировать скрипт'}
              </button>
              <button
                className="btn"
                onClick={() => downloadFile('install-svaston-vpn.sh', serverScript)}
              >
                <Download size={15} /> Скачать .sh
              </button>
            </div>
          </div>
        </div>
      )}

      {qrModal && (
        <div className="modal-backdrop" onClick={() => setQrModal(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <strong>{qrModal.title}</strong>
              <button className="btn" onClick={() => setQrModal(null)}>
                <X size={16} />
              </button>
            </div>
            <div className="qr-wrap">
              <QRCodeSVG value={qrModal.value} size={220} />
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Отсканируйте в Hiddify, v2rayNG, Nekobox или Streisand
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
