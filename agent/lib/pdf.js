const http = require('http');
const https = require('https');
const crypto = require('crypto');
const asn1js = require('asn1js');
const pkijs = require('pkijs');

function ab(b) { return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength); }

function assertNoExistingSignature(pdfBytes) {
  const s = pdfBytes.toString('binary');
  if (/\/Type\s*\/Sig\b/.test(s) || /\/ByteRange\s*\[/.test(s)) {
    throw new Error('Input PDF already contains a signature. Use a fresh, unsigned PDF.');
  }
}

function getAIAUrls(cert) {
  const OID = { aiaExt: '1.3.6.1.5.5.7.1.1', aia_caIssuers: '1.3.6.1.5.5.7.48.2', aia_ocsp: '1.3.6.1.5.5.7.48.1' };
  const ext = (cert.extensions || []).find(e => e.extnID === OID.aiaExt);
  const caIssuers = [], ocsp = [];
  if (!ext) return { caIssuers, ocsp };
  const inner = asn1js.fromBER(ext.extnValue.valueBlock.valueHex).result;
  if (!inner || inner.constructor.name !== 'Sequence') return { caIssuers, ocsp };
  for (const ad of inner.valueBlock.value) {
    const oid = ad.valueBlock.value[0].valueBlock.toString();
    const gn  = ad.valueBlock.value[1];
    if (gn.idBlock.tagClass === 3 && gn.idBlock.tagNumber === 6) {
      const uri = Buffer.from(gn.valueBlock.valueHex).toString('ascii').trim();
      if (oid === OID.aia_caIssuers) caIssuers.push(uri);
      if (oid === OID.aia_ocsp)     ocsp.push(uri);
    }
  }
  return { caIssuers, ocsp };
}

async function httpGetRaw(url) {
  const mod = url.startsWith('https:') ? https : http;
  return new Promise((resolve, reject) => {
    const req = mod.get(url, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return resolve(httpGetRaw(res.headers.location));
      }
      if (res.statusCode !== 200) return reject(new Error(`GET ${url} -> HTTP ${res.statusCode}`));
      const chunks = []; res.on('data', d => chunks.push(d)); res.on('end', () => resolve(Buffer.concat(chunks)));
    });
    req.on('error', reject); req.end();
  });
}

async function fetchChainViaAIA(startCertPkijs, maxDepth = 4) {
  const chain = []; let current = startCertPkijs; const seen = new Set();
  for (let i=0; i<maxDepth; i++) {
    const { caIssuers } = getAIAUrls(current); if (!caIssuers.length) break;
    let nextDer=null, nextPkijs=null;
    for (const url of caIssuers) {
      try {
        const buf = await httpGetRaw(url);
        const der = /-----BEGIN CERTIFICATE-----/.test(buf.toString('utf8'))
          ? Buffer.from(buf.toString('utf8').replace(/-----(BEGIN|END) CERTIFICATE-----/g,'').replace(/[\r\n\s]/g,''), 'base64')
          : buf;
        const a = asn1js.fromBER(ab(der)); nextPkijs = new pkijs.Certificate({ schema: a.result }); nextDer = der; break;
      } catch {}
    }
    if (!nextPkijs) break;
    const fp = crypto.createHash('sha1').update(nextDer).digest('hex'); if (seen.has(fp)) break; seen.add(fp);
    chain.push(nextPkijs);
    if (nextPkijs.issuer.isEqual(nextPkijs.subject)) break;
    current = nextPkijs;
  }
  return chain;
}

function parseLocalTime(s) {
  if (!s) return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?$/.exec(s);
  if (!m) throw new Error("signingTime must be 'YYYY-MM-DD HH:mm:ss'");
  const [, y, mo, d, h, mi, se = '0'] = m;
  return new Date(+y, +mo-1, +d, +h, +mi, +se);
}

module.exports = {
  assertNoExistingSignature,
  fetchChainViaAIA,
  parseLocalTime,
  getAIAUrls,
};
