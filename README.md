# Pxxl Free multi-protocol Xray (Node, no Docker)

Deploy on Pxxl Free: GitHub repo only, language must be Node (`package.json`).
Do NOT pick Docker / Drop / Dockerfile on Free — paid-locked.

## Files
- `package.json` — Node detect, `npm start` -> `node server.js`
- `setup.js` — downloads Xray-linux-64.zip at build/start, unpacks `web-worker` + geoip/geosite
- `server.js` — one Node process on `$PORT`, dispatches WS upgrades by path to local Xray inbounds

## Env vars (set in Pxxl dashboard, NEVER commit)
- `UUID` — fresh UUIDv4, shared by VLESS / VMess / Trojan
- `WSPATH` — random base path, must start with `/`, e.g. `/2203793afcab9815`
- `SSPASS` — Shadowsocks password (defaults to UUID without dashes if unset)
- `PORT` — injected by Pxxl

Derived WS paths: `$WSPATH/vless`, `$WSPATH/vmess`, `$WSPATH/trojan`, `$WSPATH/ss`
All client-side: `:443`, `security=tls`, `type=ws`, `sni=host=<host>`

## Protocols
VLESS, VMess, Trojan, Shadowsocks (aes-256-gcm) — all WS+TLS.
Root `/` and unknown paths return 404. Bittorrent and private IPs/domains are blocked in Xray routing. DNS via DoH 1.1.1.1 / 8.8.8.8. Log level warning only.
