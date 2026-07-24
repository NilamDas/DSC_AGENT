const crypto = require('crypto');
const PKCS11 = require('pkcs11js');
const cfg = require('./config');
const asn1js = require('asn1js');

const A_SHA256 = Buffer.from([0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20]);
const di256 = (h) => Buffer.concat([A_SHA256, h]);
const VERIFIED_KEY_CACHE_MS = 5 * 60 * 1000;
const verifiedKeyCache = new Map();

function tryPick(candidates) {
  let fallback = null;
  for (const dll of candidates) {
    try {
      const fs = require('fs');
      if (!fs.existsSync(dll)) continue;
      const p11 = new PKCS11.PKCS11();
      p11.load(dll); p11.C_Initialize();
      try {
        const withToken = p11.C_GetSlotList(true) || [];
        const all = p11.C_GetSlotList(false) || [];
        p11.C_Finalize();
        if (withToken.length) return { dll, slotPresent: true };
        if (!fallback) fallback = { dll, slotPresent: false, totalSlots: all.length };
      } catch {
        try { p11.C_Finalize(); } catch {}
        if (!fallback) fallback = { dll, slotPresent: false };
      }
    } catch {}
  }
  if (fallback) return fallback;
  throw new Error('No PKCS#11 module found among candidates.');
}

function pickModule(preferred) {
  const DEFAULT_CANDIDATES = cfg.DEFAULT_CANDIDATES;
  const PKCS11_DLL = preferred || cfg.PKCS11_DLL;
  const candidates = PKCS11_DLL ? [PKCS11_DLL] : DEFAULT_CANDIDATES;
  return tryPick(candidates);
}

function pickFromCandidates(candidates) {
  if (!Array.isArray(candidates) || candidates.length === 0) throw new Error('No candidates provided');
  return tryPick(candidates);
}

function getKnownTokenCandidates(name) {
  const m = cfg.KNOWN_TOKENS || {};
  const t = m[name];
  return (t && Array.isArray(t.paths)) ? t.paths.slice() : [];
}

function getSlotHandle(p11, needToken = true) {
  let slots = [];
  try { slots = p11.C_GetSlotList(needToken) || []; } catch { slots = []; }
  if (!slots.length) {
    const all = p11.C_GetSlotList(false) || [];
    for (const s of all) {
      let sh = null;
      if (Buffer.isBuffer(s)) sh = s;
      else if (typeof s === 'number') { const b = Buffer.allocUnsafe(4); b.writeUInt32LE(s,0); sh = b; }
      else if (s && s.buffer && s.byteLength !== undefined) sh = Buffer.from(s.buffer, s.byteOffset||0, s.byteLength);
      if (!sh) continue;
      try {
        const tmp = p11.C_OpenSession(sh, PKCS11.CKF_SERIAL_SESSION | PKCS11.CKF_RW_SESSION);
        try { if (tmp) p11.C_CloseSession(tmp); } catch {}
        return sh;
      } catch {}
    }
    throw new Error(`No token present. Slots(with token): 0 / total: ${all.length}`);
  }
  const s0 = slots[0];
  if (Buffer.isBuffer(s0)) return s0;
  if (typeof s0 === 'number') { const b = Buffer.allocUnsafe(4); b.writeUInt32LE(s0,0); return b; }
  if (s0 && s0.buffer && s0.byteLength !== undefined) return Buffer.from(s0.buffer, s0.byteOffset||0, s0.byteLength);
  throw new Error('Unsupported slot handle type');
}

function withSession(dll, pin, fn) {
  const p11 = new PKCS11.PKCS11(); p11.load(dll); p11.C_Initialize();
  let s; try {
    const slot = getSlotHandle(p11, true);
    s = p11.C_OpenSession(slot, PKCS11.CKF_SERIAL_SESSION | PKCS11.CKF_RW_SESSION);
    if (pin) { try { p11.C_Login(s, 1, pin); } catch(e) { try { p11.C_Logout(s);} catch{}; throw e; } }
    return fn(p11, s);
  } finally {
    try { if (s) p11.C_Logout(s); } catch {}
    try { if (s) p11.C_CloseSession(s); } catch {}
    try { p11.C_Finalize(); } catch {}
  }
}

function listObjects(p11, s, template, limit = 100) {
  p11.C_FindObjectsInit(s, template);
  const out = p11.C_FindObjects(s, limit);
  p11.C_FindObjectsFinal(s);
  return out || [];
}
function getAttr(p11, s, h, type) {
  try { return p11.C_GetAttributeValue(s, h, [{ type }])[0].value; } catch { return null; }
}
function bufToHex(b){ return Buffer.from(b).toString('hex'); }
function hexEq(a,b){ return a.toLowerCase()===b.toLowerCase(); }

function verifyRSASHA256(certDER, data, sig) {
  const x = new crypto.X509Certificate(certDER);
  const v = crypto.createVerify('RSA-SHA256'); v.update(data); v.end();
  try { return v.verify(x.publicKey, sig); } catch { return false; }
}
function verifyRSAPKCS1_DI(certDER, di, sig) {
  const x = new crypto.X509Certificate(certDER);
  const em = crypto.publicDecrypt({ key: x.publicKey, padding: crypto.constants.RSA_NO_PADDING }, sig);
  let i = 0; if (em[i++]!==0x00 || em[i++]!==0x01) return false; while (i<em.length && em[i]===0xff) i++; if (em[i++]!==0x00) return false;
  return em.subarray(i).equals(di);
}

function probePair(p11, s, privHandle, certDER) {
  const msg = Buffer.from('signing-key-probe');
  try {
    p11.C_SignInit(s, { mechanism: PKCS11.CKM_SHA256_RSA_PKCS }, privHandle);
    let sig; try { sig = p11.C_Sign(s, msg); }
    catch { const out = Buffer.alloc(4096); const r = p11.C_Sign(s, msg, out); sig = Buffer.isBuffer(r)?r:out.subarray(0,r); }
    if (verifyRSASHA256(certDER, msg, sig)) return { ok:true, mech:'CKM_SHA256_RSA_PKCS' };
  } catch {}
  try {
    const di = di256(crypto.createHash('sha256').update(msg).digest());
    p11.C_SignInit(s, { mechanism: PKCS11.CKM_RSA_PKCS }, privHandle);
    let sig; try { sig = p11.C_Sign(s, di); }
    catch { const out = Buffer.alloc(4096); const r = p11.C_Sign(s, di, out); sig = Buffer.isBuffer(r)?r:out.subarray(0,r); }
    if (verifyRSAPKCS1_DI(certDER, di, sig)) return { ok:true, mech:'CKM_RSA_PKCS' };
  } catch {}
  return { ok:false };
}

function getTokenSerial(p11, session) {
  try {
    const sessionInfo = p11.C_GetSessionInfo(session);
    const slot = sessionInfo && (sessionInfo.slotID || sessionInfo.slotId || sessionInfo.slot);
    if (!slot) return '';
    const tokenInfo = p11.C_GetTokenInfo(slot);
    const rawSerial = tokenInfo && tokenInfo.serialNumber;
    return Buffer.isBuffer(rawSerial)
      ? rawSerial.toString('utf8').trim()
      : String(rawSerial || '').trim();
  } catch {
    return '';
  }
}

function clearSigningKeyCache(dll) {
  if (dll) verifiedKeyCache.delete(dll);
  else verifiedKeyCache.clear();
}

function detectSigningKey(dll, pin) {
  return withSession(dll, pin, (p11, s) => {
    const tokenSerial = getTokenSerial(p11, s);
    const cached = tokenSerial ? verifiedKeyCache.get(dll) : null;
    if (
      cached
      && cached.tokenSerial === tokenSerial
      && (Date.now() - cached.verifiedAt) < VERIFIED_KEY_CACHE_MS
    ) {
      const cachedPrivateKeys = listObjects(p11, s, [
        { type: PKCS11.CKA_CLASS, value: PKCS11.CKO_PRIVATE_KEY },
        { type: PKCS11.CKA_ID, value: Buffer.from(cached.idHex, 'hex') },
      ], 1);
      if (cachedPrivateKeys.length) {
        return {
          idHex: cached.idHex,
          certDER: Buffer.from(cached.certDER),
          tokenSerial,
        };
      }
      verifiedKeyCache.delete(dll);
    }

    const privs = listObjects(p11, s, [{ type: PKCS11.CKA_CLASS, value: PKCS11.CKO_PRIVATE_KEY }], 50)
      .map(h => ({ handle:h, id:getAttr(p11,s,h,PKCS11.CKA_ID), label:getAttr(p11,s,h,PKCS11.CKA_LABEL) }))
      .filter(x=>x.id)
      .map(x=>({ handle:x.handle, idHex:bufToHex(x.id), label:x.label?x.label.toString():'' }));
    if (!privs.length) throw new Error('No private keys on token');

    const certs = listObjects(p11, s, [{ type: PKCS11.CKA_CLASS, value: PKCS11.CKO_CERTIFICATE }], 50)
      .map(h => ({ handle:h, id:getAttr(p11,s,h,PKCS11.CKA_ID), der:getAttr(p11,s,h,PKCS11.CKA_VALUE), label:getAttr(p11,s,h,PKCS11.CKA_LABEL) }))
      .filter(x=>x.id && x.der)
      .map(x=>({ handle:x.handle, idHex:bufToHex(x.id), der:Buffer.from(x.der), label:x.label?x.label.toString():'' }));
    if (!certs.length) throw new Error('No certificates on token');

    const pairs = [];
    for (const c of certs) {
      const p = privs.find(k => hexEq(k.idHex, c.idHex));
      if (p) pairs.push({ idHex:c.idHex, priv:p, certDER:c.der });
    }
    if (!pairs.length) throw new Error('No key/cert pairs with matching CKA_ID');

    for (const pair of pairs) {
      const res = probePair(p11, s, pair.priv.handle, pair.certDER);
      if (res.ok) {
        if (tokenSerial) {
          verifiedKeyCache.set(dll, {
            tokenSerial,
            idHex: pair.idHex,
            certDER: Buffer.from(pair.certDER),
            verifiedAt: Date.now(),
          });
        }
        return { idHex: pair.idHex, certDER: pair.certDER, tokenSerial };
      }
    }
    throw new Error('No usable signing key (probe failed)');
  });
}

let picked = null;
function ensureDllPicked() { if (!picked) picked = pickModule(); return picked; }

module.exports = {
  di256,
  pickModule,
  pickFromCandidates,
  getKnownTokenCandidates,
  ensureDllPicked,
  withSession,
  listObjects,
  getAttr,
  bufToHex,
  hexEq,
  detectSigningKey,
  clearSigningKeyCache,
};

// New: list key/cert pairs for UI selection (best-effort without login)
function listPairs(dll, pin = '') {
  return withSession(dll, pin, (p11, s) => {
    const privs = listObjects(p11, s, [{ type: PKCS11.CKA_CLASS, value: PKCS11.CKO_PRIVATE_KEY }], 200)
      .map(h => ({ handle:h, id:getAttr(p11,s,h,PKCS11.CKA_ID), label:getAttr(p11,s,h,PKCS11.CKA_LABEL) }))
      .filter(x=>x.id)
      .map(x=>({ handle:x.handle, idHex:bufToHex(x.id), label:x.label?String(x.label):'' }));

    const certs = listObjects(p11, s, [{ type: PKCS11.CKA_CLASS, value: PKCS11.CKO_CERTIFICATE }], 200)
      .map(h => ({ handle:h, id:getAttr(p11,s,h,PKCS11.CKA_ID), der:getAttr(p11,s,h,PKCS11.CKA_VALUE), label:getAttr(p11,s,h,PKCS11.CKA_LABEL) }))
      .filter(x=>x.id && x.der)
      .map(x=>({ handle:x.handle, idHex:bufToHex(x.id), der:Buffer.from(x.der), label:x.label?String(x.label):'' }));

    const pairs = [];
    for (const c of certs) {
      const p = privs.find(k => hexEq(k.idHex, c.idHex));
      if (!p) continue;
      let subjectCN = 'Unknown';
      try {
        const xc = new crypto.X509Certificate(c.der);
        // subject: 'CN=Name, O=Org, C=IN' — extract CN
        const m = /CN=([^,]+)/.exec(xc.subject);
        if (m && m[1]) subjectCN = m[1].trim();
      } catch {}
      pairs.push({ ckaIdHex: c.idHex, subjectCN, label: c.label || p.label || '' });
    }
    return pairs;
  });
}

module.exports.listPairs = listPairs;
