// Pxxl Free multi-protocol node: VLESS + VMess + Trojan + Shadowsocks
// All over WS (plain inside container, TLS terminated by Pxxl edge on :443).
// Pxxl only forwards ONE $PORT to the container, so this Node process
// dispatches WebSocket upgrades by path to four local Xray inbounds.
// Secrets come ONLY from env vars (UUID / WSPATH / SSPASS) - never commit them.
const fs = require('fs');
const path = require('path');
const http = require('http');
const net = require('net');
const { spawn, execSync } = require('child_process');
const crypto = require('crypto');

const uuid = process.env.UUID || process.env.APP_KEY;
const ssPass = process.env.SSPASS || (uuid ? uuid.replace(/-/g, '') : null);
const wsBase = (process.env.WSPATH || process.env.API_ROUTE || '/api/v1/sync').replace(/\/$/, '');
const port = parseInt(process.env.PORT || '8080', 10);
if (!uuid) { console.error('UUID required'); process.exit(1); }
if (!wsBase.startsWith('/')) { console.error('WSPATH must start with /'); process.exit(1); }

const paths = {
  vless: wsBase + '/vless',
  vmess: wsBase + '/vmess',
  trojan: wsBase + '/trojan',
  ss: wsBase + '/ss',
};
const localPorts = { vless: 11001, vmess: 11002, trojan: 11003, ss: 11004 };

const bin = path.join(__dirname, 'web-worker');
if (!fs.existsSync(bin)) {
  try { execSync('node setup.js', { stdio: 'inherit', cwd: __dirname }); }
  catch (e) { process.exit(1); }
}

function wsInbound(protocol, localPort, wsPath, settings) {
  return {
    listen: '127.0.0.1', port: localPort, protocol,
    settings,
    streamSettings: { network: 'ws', wsSettings: { path: wsPath } },
    sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] },
  };
}

const cfg = {
  log: { loglevel: 'warning' },
  inbounds: [
    wsInbound('vless', localPorts.vless, paths.vless,
      { clients: [{ id: uuid }], decryption: 'none' }),
    wsInbound('vmess', localPorts.vmess, paths.vmess,
      { clients: [{ id: uuid, alterId: 0 }] }),
    wsInbound('trojan', localPorts.trojan, paths.trojan,
      { clients: [{ password: uuid }] }),
    wsInbound('shadowsocks', localPorts.ss, paths.ss,
      { method: 'aes-256-gcm', password: ssPass }),
  ],
  outbounds: [
    { protocol: 'freedom', tag: 'direct', settings: { domainStrategy: 'UseIPv4' } },
    { protocol: 'blackhole', tag: 'block' },
  ],
  routing: {
    domainStrategy: 'IPIfNonMatch',
    rules: [
      { type: 'field', outboundTag: 'block', protocol: ['bittorrent'] },
      { type: 'field', outboundTag: 'block', ip: ['geoip:private'] },
      { type: 'field', outboundTag: 'block', domain: ['geosite:private'] },
    ],
  },
  dns: { servers: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'], queryStrategy: 'UseIPv4' },
};
const cfgPath = path.join('/tmp', 'runtime-' + crypto.randomBytes(4).toString('hex') + '.json');
fs.writeFileSync(cfgPath, JSON.stringify(cfg));
const child = spawn(bin, ['run', '-c', cfgPath], { stdio: 'inherit', cwd: __dirname });
child.on('exit', (c) => process.exit(c || 0));
process.on('SIGTERM', () => child.kill('SIGTERM'));

const route = {};
for (const k of Object.keys(paths)) route[paths[k]] = localPorts[k];

const server = http.createServer((req, res) => {
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('404 Not Found');
});
server.on('upgrade', (req, socket, head) => {
  let pathname = '';
  try { pathname = new URL(req.url, 'http://127.0.0.1').pathname; } catch (e) { socket.destroy(); return; }
  const targetPort = route[pathname];
  if (!targetPort) { socket.destroy(); return; }
  const target = net.connect(targetPort, '127.0.0.1', () => {
    let header = req.method + ' ' + req.url + ' HTTP/1.1\r\n';
    for (const [k, v] of Object.entries(req.headers)) header += k + ': ' + v + '\r\n';
    header += '\r\n';
    target.write(header);
    if (head && head.length) target.write(head);
    socket.pipe(target);
    target.pipe(socket);
  });
  const onErr = () => { try { socket.destroy(); } catch (e) {} try { target.destroy(); } catch (e) {} };
  socket.on('error', onErr);
  target.on('error', onErr);
});
server.listen(port, '0.0.0.0', () => {
  console.log('listening on ' + port + ' paths: ' + Object.values(paths).join(','));
});
