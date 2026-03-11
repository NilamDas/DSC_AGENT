const http = require('http');
const https = require('https');

async function promptPinInteractive(urlStr, bearerToken, hintMessage) {
  if (!urlStr) throw new Error('PIN prompt not available');
  const payload = JSON.stringify({ message: hintMessage || 'Enter token PIN' });
  const url = new URL(urlStr);
  const opts = {
    hostname: url.hostname,
    port: url.port,
    path: url.pathname,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
      'Authorization': `Bearer ${bearerToken}`,
    },
  };
  const client = url.protocol === 'https:' ? https : http;
  return await new Promise((resolve, reject) => {
    const req = client.request(opts, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => {
        try {
          const j = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (j && j.ok && typeof j.pin === 'string') return resolve(j.pin);
          if (j && j.canceled) return reject(new Error('PIN entry canceled'));
          return reject(new Error(j && j.message ? j.message : 'PIN prompt failed'));
        } catch (e) {
          reject(e);
        }
      });
    });
    req.setTimeout(120000, () => { try { req.destroy(); } catch {}; reject(new Error('PIN prompt timeout')); });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

module.exports = { promptPinInteractive };
