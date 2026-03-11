// ==============================================
// File: dsc-agent.js  (local client service)
// =============================================
// A tiny localhost HTTP service that any web app can call via JavaScript
// to sign PDFs with a USB DSC token (PKCS#11). Minimal config: it auto-detects
// the signing key (even when the token exposes separate encryption/signing keys).



// Endpoints
//  GET  /health                 ? { ok: true, version, dll, slotPresent }
//  POST /sign/pdf               ? { pdfBase64, reason?, profile?, embedIntermediates?, includeESS?, signingTime? (YYYY-MM-DD HH:mm:ss), pin? }
//                                ? { ok: true, signedPdfBase64 }
//  GET  /certs                  ? { ok: true, pairs:[{ckaIdHex, subjectCN, label}] }
//
// Security (dev defaults)
//  - Binds to 127.0.0.1 only. CORS allowlist via ALLOW_ORIGINS env (default: *)
//  - PIN may be passed per-request (or set via DSC_PIN env). Do NOT log the PIN.
//
// Usage
//   npm i express pkcs11js pkijs asn1js @signpdf/signpdf @signpdf/placeholder-plain @signpdf/utils
//   set ALLOW_ORIGINS=http://localhost:3000,http://yourapp.example
//   set DSC_PIN=123456    (or send pin in request body)
//   node dsc-agent.js

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const http = require('http');
const https = require('https');
const PKCS11 = require('pkcs11js');
const asn1js = require('asn1js');
const pkijs = require('pkijs');
const { plainAddPlaceholder } = require('@signpdf/placeholder-plain');
const { pdflibAddPlaceholder } = require('@signpdf/placeholder-pdf-lib');
const { SignPdf } = require('@signpdf/signpdf');
const { Signer } = require('@signpdf/utils');
const { PDFDocument, rgb, StandardFonts, PDFName, PDFNumber, PDFString } = require('pdf-lib'); // UPDATE THIS LINE
const cfg = require('./lib/config');
const pinPromptClient = require('./lib/pinPromptClient');
const pkcs11lib = require('./lib/pkcs11');
const pdfUtil = require('./lib/pdf');

const VERSION = '0.1.0';

// ---------- config ----------
const DEFAULT_CANDIDATES = cfg.DEFAULT_CANDIDATES;
const PKCS11_DLL = cfg.PKCS11_DLL;
const DSC_PIN_ENV = cfg.DSC_PIN_ENV;
const PORT = cfg.PORT;
const ALLOW = cfg.ALLOW;
const AUTH_TOKEN = cfg.AUTH_TOKEN;
const ALLOW_LOCAL_SHUTDOWN = cfg.ALLOW_LOCAL_SHUTDOWN;
const REQUIRE_PIN_PER_SIGN = cfg.REQUIRE_PIN_PER_SIGN;
const PIN_PROMPT_URL = cfg.PIN_PROMPT_URL;
const PIN_PROMPT_TOKEN = cfg.PIN_PROMPT_TOKEN;
const SIGN_RECT = cfg.SIGN_RECT;
const MAX_BODY_MB = cfg.MAX_BODY_MB;
const LTV_ENABLE = cfg.LTV_ENABLE;
const LTV_STRICT = cfg.LTV_STRICT;

// In-memory session PIN (optional, process-lifetime only)
let SESSION_PIN = '';
let USER_SELECTED_DLL = '';
let USER_SELECTED_TOKEN = '';

const OID = {
  data: '1.2.840.113549.1.7.1',
  signedData: '1.2.840.113549.1.7.2',
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha256WithRSA: '1.2.840.113549.1.1.11',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5',
  signingCertV2: '1.2.840.113549.1.9.16.2.47',
  adbeRevInfoArchival: '1.2.840.113583.1.1.8',
  ocspBasic: '1.3.6.1.5.5.7.48.1.1',
  aiaExt: '1.3.6.1.5.5.7.1.1',
  aia_caIssuers: '1.3.6.1.5.5.7.48.2',
  aia_ocsp: '1.3.6.1.5.5.7.48.1',
  crlDistPoints: '2.5.29.31',
};
const A_SHA256 = Buffer.from([0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20]);
const di256 = (h) => Buffer.concat([A_SHA256, h]);
const ab = (b) => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);

// ---------- helpers ----------
// Robustly load PDFs even when inputs have BOM/prefix bytes or minor issues
function normalizePdfBuffer(input) {
  let buf = input;
  try {
    if (typeof input === 'string') {
      const s = input.trim();
      try { buf = Buffer.from(s.replace(/\s+/g, ''), 'base64'); }
      catch { buf = Buffer.from(s, 'binary'); }
    } else if (!Buffer.isBuffer(input)) {
      if (input && input.buffer && input.byteLength !== undefined) buf = Buffer.from(input.buffer, input.byteOffset || 0, input.byteLength);
      else buf = Buffer.from(input || []);
    }
  } catch { buf = Buffer.isBuffer(input) ? input : Buffer.from([]); }
  if (!buf || buf.length < 5) return buf;
  // Strip UTF-8 BOM
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) buf = buf.subarray(3);
  try {
    // If %PDF- is not at position 0, try to locate and trim leading bytes
    if (!(buf[0] === 0x25 && buf[1] === 0x50 && buf[2] === 0x44 && buf[3] === 0x46 && buf[4] === 0x2d)) {
      const at = buf.indexOf('%PDF-');
      if (at > 0) return buf.subarray(at);
      const head = buf.subarray(0, Math.min(2*1024*1024, buf.length)).toString('latin1');
      const at2 = head.indexOf('%PDF-');
      if (at2 > 0) return buf.subarray(at2);
    }
  } catch {}
  return buf;
}

async function safeLoadPdf(input) {
  try { return await PDFDocument.load(input); }
  catch (e) {
    const msg = (e && e.message) || '';
    if (/No PDF header found/i.test(msg) || /Failed to parse PDF document/i.test(msg)) {
      const norm = normalizePdfBuffer(input);
      return PDFDocument.load(norm);
    }
    throw e;
  }
}

// Ensure a rectangle stays within page bounds and has a minimum size
function clampRectToPage(rect, pageSize) {
  try {
    let [x1, y1, x2, y2] = rect.map((n) => Number(n) || 0);
    const W = Math.max(0, pageSize.width || 0);
    const H = Math.max(0, pageSize.height || 0);
    const minW = 12, minH = 12;
    x1 = Math.max(0, Math.min(W, x1));
    x2 = Math.max(0, Math.min(W, x2));
    y1 = Math.max(0, Math.min(H, y1));
    y2 = Math.max(0, Math.min(H, y2));
    if (x2 < x1) { const t = x1; x1 = x2; x2 = t; }
    if (y2 < y1) { const t = y1; y1 = y2; y2 = t; }
    if ((x2 - x1) < minW) x2 = Math.min(W, x1 + minW);
    if ((y2 - y1) < minH) y2 = Math.min(H, y1 + minH);
    return [x1, y1, x2, y2];
  } catch { return rect; }
}
function cors(req, res, next) {
  const origin = req.headers.origin || '';
  const allowed = ALLOW.includes('*') || ALLOW.includes(origin);
  if (allowed) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Headers', 'content-type,x-dsc-auth');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
}

function requireAuth(req, res, next) {
  if (!AUTH_TOKEN) return next(); // dev mode: no token set
  const provided = req.headers['x-dsc-auth'];
  if (typeof provided === 'string' && provided === AUTH_TOKEN) return next();
  return res.status(401).json({ ok: false, message: 'Unauthorized' });
}

async function promptPinInteractive(hintMessage) {
  return pinPromptClient.promptPinInteractive(PIN_PROMPT_URL, PIN_PROMPT_TOKEN, hintMessage);
}

function pickModule() { return pkcs11lib.pickModule(USER_SELECTED_DLL || undefined); }

function getSlotHandle(p11, needToken = true) {
  let slots = [];
  try { slots = p11.C_GetSlotList(needToken) || []; } catch { slots = []; }
  if (!slots.length) {
    const all = p11.C_GetSlotList(false) || [];
    // Fallback: probe all slots by attempting to open a session
    for (const s of all) {
      let sh = null;
      if (Buffer.isBuffer(s)) sh = s;
      else if (typeof s === 'number') { const b = Buffer.allocUnsafe(4); b.writeUInt32LE(s,0); sh = b; }
      else if (s && s.buffer && s.byteLength !== undefined) sh = Buffer.from(s.buffer, s.byteOffset||0, s.byteLength);
      if (!sh) continue;
      try {
        const tmp = p11.C_OpenSession(sh, PKCS11.CKF_SERIAL_SESSION | PKCS11.CKF_RW_SESSION);
        try { if (tmp) p11.C_CloseSession(tmp); } catch {}
        return sh; // usable slot found
        // Optional hard override for testing: force top-left placement
        try {
          const forceTopLeft = !!(req.body && req.body.forceTopLeft === true);
          if (forceTopLeft) {
            const w = Math.max(1, placeholderRect[2] - placeholderRect[0]);
            const h = Math.max(1, placeholderRect[3] - placeholderRect[1]);
            const marginTL = 36;
            const x1tl = marginTL;
            const y2tl = Math.max(0, szTMP.height - marginTL);
            const x2tl = Math.min(szTMP.width, x1tl + w);
            const y1tl = Math.max(0, y2tl - h);
            placeholderRect = clampRectToPage([x1tl, y1tl, x2tl, y2tl], szTMP);
          }
        } catch {}
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

function withSession(dll, pin, fn) { return pkcs11lib.withSession(dll, pin, fn); }

// pkcs11 helpers are accessed via pkcs11lib directly to avoid duplication

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

function detectSigningKey(dll, pin) { return pkcs11lib.detectSigningKey(dll, pin); }

function getAIAUrls(cert) {
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
      if (res.statusCode !== 200) return reject(new Error(`GET ${url} ? HTTP ${res.statusCode}`));
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
          ? Buffer.from(buf.toString('utf8').replace(/-----(BEGIN|END) CERTIFICATE-----/g,'').replace(/[\\r\\n\s]/g,''), 'base64')
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
  return chain; // intermediates only
}

function makeSigningCertificateV2(certDER) {
  const certHash = crypto.createHash('sha256').update(certDER).digest();
  return new asn1js.Sequence({ value: [ new asn1js.Sequence({ value: [ new asn1js.Sequence({ value: [ new asn1js.OctetString({ valueHex: ab(certHash) }) ] }) ] }) ] });
}

// Remove existing signature fields and DocMDP/Perms so we can re-sign as a fresh PDF.
// Best-effort: drops form fields of type /Sig and their widgets from pages; clears /Perms.DocMDP; sets /NeedAppearances true.
// Does not attempt to preserve the visual appearance of previous signatures (no flattening of AP to page content).
async function stripSignaturesAndPerms(pdfBytes) {
  try {
    const pdfDoc = await PDFDocument.load(pdfBytes);
    const context = pdfDoc.context;
    const catalog = pdfDoc.catalog;

    // Clear DocMDP permissions if present
    try {
      const perms = catalog.lookupMaybe ? catalog.lookupMaybe(PDFName.of('Perms')) : null;
      if (perms && perms.delete) perms.delete(PDFName.of('DocMDP'));
    } catch {}

    // Enable viewer-generated appearances as a safe default
    try { catalog.set(PDFName.of('NeedAppearances'), context.obj(true)); } catch {}

    // Remove signature fields from AcroForm and associated widgets from pages
    try {
      const acro = catalog.lookupMaybe ? catalog.lookupMaybe(PDFName.of('AcroForm')) : null;
      if (acro) {
        const fields = acro.lookupMaybe ? acro.lookupMaybe(PDFName.of('Fields')) : null;
        if (fields && typeof fields.size === 'number' && fields.get) {
          const toKeep = [];
          const sigFieldRefs = new Set();
          for (let i = 0; i < fields.size(); i++) {
            const ref = fields.get(i);
            const field = context.lookup(ref);
            let isSig = false;
            try { const ft = field.lookup(PDFName.of('FT')); isSig = (ft && ft.toString && ft.toString() === '/Sig'); } catch {}
            if (isSig) {
              sigFieldRefs.add(ref && ref.toString ? ref.toString() : String(ref));
            } else {
              toKeep.push(ref);
            }
          }
          // Replace fields array with non-signature fields
          try { if (fields.array) { fields.array = toKeep; } } catch {}

          // Remove widgets that belong to removed signature fields
          const pages = pdfDoc.getPages();
          for (const page of pages) {
            try {
              const annots = page.node.lookupMaybe ? page.node.lookupMaybe(PDFName.of('Annots')) : null;
              if (!annots || !annots.size || !annots.get) continue;
              const keepAnnots = [];
              for (let j = 0; j < annots.size(); j++) {
                const aref = annots.get(j);
                const annot = context.lookup(aref);
                let drop = false;
                try {
                  const subtype = annot.lookup(PDFName.of('Subtype'));
                  if (subtype && subtype.toString && subtype.toString() === '/Widget') {
                    const parentRef = annot.lookupMaybe ? annot.lookupMaybe(PDFName.of('Parent')) : null;
                    const key = parentRef && parentRef.toString ? parentRef.toString() : (aref && aref.toString ? aref.toString() : '');
                    if (sigFieldRefs.has(key)) drop = true;
                  }
                } catch {}
                if (!drop) keepAnnots.push(aref);
              }
              // Replace annotations array
              try { if (annots.array) { annots.array = keepAnnots; } } catch {}
            } catch {}
          }
        }
        // Normalize SigFlags
        try { acro.set(PDFName.of('SigFlags'), PDFNumber.of(0)); } catch {}
      }
    } catch {}

    return await pdfDoc.save({ useObjectStreams: false });
  } catch (e) {
    // If parsing fails (e.g., encrypted), surface the original error to caller
    throw e;
  }
}

// Best-effort extraction of previous signature widgets: page, rect, name, date
async function extractPreviousSignerLines(pdfBytes) {
  const lines = [];
  try {
    const doc = await PDFDocument.load(pdfBytes);
    const context = doc.context; const catalog = doc.catalog;
    const pageKey = (ref) => (ref && ref.toString ? ref.toString() : String(ref || ''));
    // Build a map of page ref key -> index
    const pageMap = new Map();
    const pages = doc.getPages();
    for (let i = 0; i < pages.length; i++) { try { pageMap.set(pageKey(pages[i].ref), i); } catch {} }

    let acro = null; try { acro = catalog.lookup(PDFName.of('AcroForm')); } catch {}
    if (!acro) return [];
    let fields = null; try { fields = acro.lookup(PDFName.of('Fields')); } catch {}
    if (!fields || !fields.size || !fields.get) return [];
    const results = [];
    for (let i = 0; i < fields.size(); i++) {
      try {
        const ref = fields.get(i); const field = context.lookup(ref);
        let isSig = false; try { const ft = field.lookup(PDFName.of('FT')); isSig = (ft && ft.toString && ft.toString() === '/Sig'); } catch {}
        if (!isSig) continue;
        let name = ''; let when = '';
        try { const v = field.lookup(PDFName.of('V')); if (v) {
          try { const n = v.lookup(PDFName.of('Name')); if (n && n.decodeText) name = n.decodeText(); } catch {}
          try { const m = v.lookup(PDFName.of('M')); if (m && m.decodeText) when = m.decodeText(); } catch {}
        }} catch {}
        if (!name) { try { const t = field.lookup(PDFName.of('T')); if (t && t.decodeText) name = t.decodeText(); } catch {} }

        const widgets = [];
        try {
          const kids = field.lookup(PDFName.of('Kids'));
          if (kids && kids.size && kids.get) {
            for (let k = 0; k < kids.size(); k++) widgets.push(kids.get(k));
          }
        } catch {}
        if (widgets.length === 0) widgets.push(ref);

        for (const wref of widgets) {
          try {
            const widget = context.lookup(wref);
            const rectArr = widget.lookup(PDFName.of('Rect'));
            const x1 = rectArr.get(0).asNumber();
            const y1 = rectArr.get(1).asNumber();
            const x2 = rectArr.get(2).asNumber();
            const y2 = rectArr.get(3).asNumber();
            let pidx = 0;
            try { const pref = widget.lookup(PDFName.of('P')); const key = pageKey(pref); if (pageMap.has(key)) pidx = pageMap.get(key); } catch {}
            results.push({ pageIndex: pidx, rect: [x1, y1, x2, y2], name, when });
          } catch {}
        }
      } catch {}
    }
    return results;
  } catch {}
  return [];
}

async function stampPreviousSignersNote(pdfBytes, lines, position = { x: 36, y: 'top', size: 9 }) {
  // Retained for backward compatibility; draw simple lines on first page
  if (!Array.isArray(lines) || lines.length === 0) return pdfBytes;
  const doc = await PDFDocument.load(pdfBytes);
  const page = doc.getPage(0);
  const { width, height } = page.getSize();
  const helv = await doc.embedFont(StandardFonts.Helvetica);
  let y = typeof position.y === 'number' ? position.y : (height - 24);
  const x = position.x || 36; const size = position.size || 9;
  const maxWidth = width - x - 36;
  const fit = (t) => { let s = String(t); while (helv.widthOfTextAtSize(s, size) > maxWidth && s.length > 4) s = s.slice(0, -1); return s; };
  for (let i = 0; i < Math.min(lines.length, 3); i++) { const text = fit(lines[i]); page.drawText(text, { x, y, size, font: helv }); y -= (size + 4); }
  return await doc.save({ useObjectStreams: false });
}

class TokenSigner extends Signer {
  constructor({ dll, pin, signerCert, intermediates, includeESS, signingTime }) {
    super(); this.dll = dll; this.pin = pin; this.signerCert = signerCert; this.intermediates = intermediates||[]; this.includeESS = !!includeESS; this.signingTime = signingTime || null;
  }
  signWithToken(innerSetDER, detectedIdHex) {
    return withSession(this.dll, this.pin, (p11, s) => {
      p11.C_FindObjectsInit(s, [ { type: PKCS11.CKA_CLASS, value: PKCS11.CKO_PRIVATE_KEY }, { type: PKCS11.CKA_ID, value: Buffer.from(detectedIdHex, 'hex') } ]);
      const [priv] = p11.C_FindObjects(s, 1); p11.C_FindObjectsFinal(s);
      if (!priv) throw new Error('Detected private key not found');
      try {
        p11.C_SignInit(s, { mechanism: PKCS11.CKM_SHA256_RSA_PKCS }, priv);
        try { return p11.C_Sign(s, innerSetDER); }
        catch { const out = Buffer.alloc(4096); const r = p11.C_Sign(s, innerSetDER, out); return Buffer.isBuffer(r)?r:out.subarray(0,r); }
      } catch {}
      const di = di256(crypto.createHash('sha256').update(innerSetDER).digest());
      p11.C_SignInit(s, { mechanism: PKCS11.CKM_RSA_PKCS }, priv);
      try { return p11.C_Sign(s, di); }
      catch { const out = Buffer.alloc(4096); const r = p11.C_Sign(s, di, out); return Buffer.isBuffer(r)?r:out.subarray(0,r); }
    });
  }
  async sign(byteRangeBuffer) {
    const pdfDigest = crypto.createHash('sha256').update(byteRangeBuffer).digest();
    const certDER = Buffer.from(this.signerCert.toSchema().toBER(false));

    const attrs = [
      new pkijs.Attribute({ type: OID.contentType,   values: [ new asn1js.ObjectIdentifier({ value: OID.data }) ] }),
      new pkijs.Attribute({ type: OID.messageDigest, values: [ new asn1js.OctetString({ valueHex: ab(pdfDigest) }) ] }),
    ];
    if (this.includeESS) attrs.push(new pkijs.Attribute({ type: OID.signingCertV2, values: [ makeSigningCertificateV2(certDER) ] }));
    if (this.signingTime) attrs.push(new pkijs.Attribute({ type: OID.signingTime, values: [ new pkijs.Time({ type: 0, value: this.signingTime }).toSchema() ] }));

    const sd = new pkijs.SignedData({
      version: 1,
      digestAlgorithms: [ new pkijs.AlgorithmIdentifier({ algorithmId: OID.sha256 }) ],
      encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: OID.data }),
      certificates: [ this.signerCert, ...this.intermediates ],
      signerInfos: []
    });
    const si = new pkijs.SignerInfo({
      version: 1,
      sid: new pkijs.IssuerAndSerialNumber({ issuer: this.signerCert.issuer, serialNumber: this.signerCert.serialNumber }),
      digestAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: OID.sha256 }),
      signatureAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: OID.sha256WithRSA }),
      signedAttrs: new pkijs.SignedAndUnsignedAttributes({ type: 0, attributes: attrs })
    });
    sd.signerInfos.push(si);

    const attrSchemas = si.signedAttrs.attributes.map(a => a.toSchema());
    const attrDERs    = attrSchemas.map(s => Buffer.from(s.toBER(false))).sort(Buffer.compare);
    const sortedSchemas = attrDERs.map(der => asn1js.fromBER(ab(der)).result);
    const innerSetDER  = Buffer.from(new asn1js.Set({ value: sortedSchemas }).toBER(false));

    // Detect correct key (id + cert) fresh per call to avoid stale state
    const { idHex: DETECTED_CKA_ID_HEX } = detectSigningKey(this.dll, this.pin);
    const sig = this.signWithToken(innerSetDER, DETECTED_CKA_ID_HEX);
    si.signature = new asn1js.OctetString({ valueHex: ab(sig) });

    // Optionally add LTV revocation info as unsigned attribute(s)
    if (LTV_ENABLE) {
      try {
        const attrs = [];
        const adobe = await buildRevocationInfoUnsignedAttr(this.signerCert, this.intermediates);
        if (adobe) attrs.push(adobe);
        if (LTV_STRICT) {
          const etsi = await buildEtsiRevocationValuesUnsignedAttr(this.signerCert, this.intermediates);
          if (etsi) attrs.push(etsi);
        }
        if (attrs.length) {
          si.unsignedAttrs = new pkijs.SignedAndUnsignedAttributes({ type: 1, attributes: attrs });
        }
      } catch {}
    }

  const ci = new pkijs.ContentInfo({ contentType: OID.signedData, content: sd.toSchema(true) });
  return Buffer.from(ci.toSchema(true).toBER(false));
  }
}

function assertNoExistingSignature(pdfBytes) { return pdfUtil.assertNoExistingSignature(pdfBytes); }

async function fetchIntermediatesIfRequested(signerCert, embed) { if (!embed) return []; return pdfUtil.fetchChainViaAIA(signerCert); }

function parseLocalTime(s) { return pdfUtil.parseLocalTime(s); }

// Normalize page selection from request to a consistent value
// Returns 'last' or a positive integer (1-based)
function normalizeRequestedPageIndex(pageReq) {
  try {
    if (pageReq === undefined || pageReq === null) return 'last';
    if (pageReq === 'last' || pageReq === '' || pageReq === false) return 'last';
    if (typeof pageReq === 'number') return pageReq > 0 ? pageReq : 'last';
    const n = parseInt(pageReq, 10);
    return (Number.isFinite(n) && n > 0) ? n : 'last';
  } catch { return 'last'; }
}

// Optionally skip stamping on one page (e.g., the page where the clickable widget lives)
// skipPage can be 'last' or a 1-based page number
async function applyTextStampToAllPages(pdfBytes, userName, signingTime, rect, anchor, skipPage = null) {
  const pdfDoc = await PDFDocument.load(pdfBytes);
  const helv = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const [rx1, ry1, rx2, ry2] = rect;
  const x1d = Math.min(rx1, rx2), x2d = Math.max(rx1, rx2);
  const y1d = Math.min(ry1, ry2), y2d = Math.max(ry1, ry2);
  const pad = (n) => String(n).padStart(2, '0');
  const dt = signingTime || new Date();
  const tsText = `${dt.getFullYear()}-${pad(dt.getMonth()+1)}-${pad(dt.getDate())} ${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`;
  const line1 = `Digitally signed by ${userName}`;
  const line2 = `Date: ${tsText}`;
  const fontSize = 10;
  const lh = 14;
  const padX = 6, padY = 6;
  const pages = pdfDoc.getPages();
  // Determine target index to skip, if requested
  let skipIndex = -1;
  if (skipPage === 'last') skipIndex = pages.length - 1;
  else if (typeof skipPage === 'number') skipIndex = Math.max(0, Math.min(pages.length - 1, skipPage - 1));
  for (let i = 0; i < pages.length; i++) {
    if (i === skipIndex) continue;
    const page = pages[i];
    const x1 = x1d, x2 = x2d, y1 = y1d, y2 = y2d;
    const wMax = Math.max(0, x2 - x1);
    const hMax = Math.max(0, y2 - y1);
    const fitText = (t, maxW) => {
      let s = String(t);
      while (helv.widthOfTextAtSize(s, fontSize) > maxW && s.length > 1) s = s.slice(0, -1);
      if (helv.widthOfTextAtSize(s, fontSize) > maxW && s.length > 1) s = s.slice(0, -1);
      return s;
    };
    const maxTextW = Math.max(0, wMax - padX*2);
    const line1Fit = fitText(line1, maxTextW);
    const line2Fit = fitText(line2, maxTextW);
    const contentW = Math.max(helv.widthOfTextAtSize(line1Fit, fontSize), helv.widthOfTextAtSize(line2Fit, fontSize));
    const w = Math.min(wMax, Math.ceil(contentW) + padX*2);
    const h = Math.min(hMax, (2*fontSize) + (lh - fontSize) + padY*2);
    let newX1 = x1, newY1 = y1, newX2 = x2, newY2 = y2;
    switch (anchor) {
      case 'top-right':
        newX2 = x2; newX1 = newX2 - w; newY2 = y2; newY1 = newY2 - h; break;
      case 'bottom-left':
        newX1 = x1; newX2 = newX1 + w; newY1 = y1; newY2 = newY1 + h; break;
      case 'bottom-right':
        newX2 = x2; newX1 = newX2 - w; newY1 = y1; newY2 = newY1 + h; break;
      case 'top-left':
      default:
        newX1 = x1; newX2 = newX1 + w; newY2 = y2; newY1 = newY2 - h; break;
    }
    // Background white box for contrast
    try { page.drawRectangle({ x: newX1, y: newY1, width: Math.max(0,w), height: Math.max(0,h), color: rgb(1,1,1), opacity: 0.85, borderOpacity: 0 }); } catch {}
    const yTop = Math.max(0, newY1 + h - padY - fontSize);
    try { page.drawText(line1Fit, { x: newX1 + padX, y: yTop, size: fontSize, font: helv, color: rgb(0,0,0) }); } catch {}
    try { page.drawText(line2Fit, { x: newX1 + padX, y: Math.max(0, yTop - lh), size: fontSize, font: helv, color: rgb(0,0,0) }); } catch {}
  }
  return await pdfDoc.save({ useObjectStreams: false });
}
async function buildPlaceholderWithVisibleStamp(pdfInputBytes, userName, reason, signingTime, rectOverride, rectMode, anchor, requestedPageIndex, stampAllPages) {
  // First load with proper options
  const pdfDoc = await PDFDocument.load(pdfInputBytes, {
    updateMetadata: false,
    ignoreEncryption: true,
    addDefaultPage: false,
    preservePDFForm: true
  });
  
  const pageCount = pdfDoc.getPageCount();
  const targetIndex = (requestedPageIndex === 'last') ? (pageCount - 1) 
    : (requestedPageIndex && requestedPageIndex > 0 ? Math.min(pageCount - 1, requestedPageIndex - 1) : 0);
  const targetPage = pdfDoc.getPages()[targetIndex];
  const pageSize = targetPage.getSize();

  // Calculate base text dimensions
  const helv = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontSize = 10;
  const lineSpacing = 14;
  const padX = 6, padY = 6;

  const pad = (n) => String(n).padStart(2, '0');
  const dt = signingTime || new Date();
  const tsText = `${dt.getFullYear()}-${pad(dt.getMonth()+1)}-${pad(dt.getDate())} ${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`;
  const line1 = `Digitally signed by ${userName}`;
  const line2 = `Date: ${tsText}`;

  // Calculate required text width and height
  const line1Width = helv.widthOfTextAtSize(line1, fontSize);
  const line2Width = helv.widthOfTextAtSize(line2, fontSize);
  const textWidth = Math.max(line1Width, line2Width);
  const textHeight = (2 * fontSize) + (lineSpacing - fontSize);

  // Add padding to get final box dimensions
  const boxWidth = Math.ceil(textWidth) + (padX * 2);
  const boxHeight = textHeight + (padY * 2);

  // Calculate rectangle based on input mode
  let x1, y1, x2, y2;
  
  if (rectOverride) {
    if (rectMode === 'top-left') {
      // User provided [left, top] coordinates
      const left = Number(rectOverride[0]) || 0;
      const top = Number(rectOverride[1]) || 0;
      
      x1 = Math.max(0, Math.min(pageSize.width - boxWidth, left));
      y2 = Math.max(boxHeight, Math.min(pageSize.height, pageSize.height - top));
      x2 = x1 + boxWidth;
      y1 = y2 - boxHeight;
    } else {
      // User provided full rectangle [x1,y1,x2,y2]
      [x1, y1, x2, y2] = rectOverride;
      
      // Ensure minimum size
      if (x2 - x1 < boxWidth) x2 = x1 + boxWidth;
      if (y2 - y1 < boxHeight) y2 = y1 + boxHeight;
    }
  } else {
    // Use default position (SIGN_RECT)
    [x1, y1, x2, y2] = SIGN_RECT;
  }

  // Clamp to page bounds
  x1 = Math.max(0, Math.min(pageSize.width - boxWidth, x1));
  x2 = Math.min(pageSize.width, x1 + boxWidth);
  y1 = Math.max(0, y1);
  y2 = Math.min(pageSize.height, Math.max(y1 + boxHeight, y2));

  // Apply anchor positioning if specified
  const finalRect = [x1, y1, x2, y2];
  switch (anchor) {
    case 'top-right':
      finalRect[0] = x2 - boxWidth;
      finalRect[2] = x2;
      finalRect[1] = y2 - boxHeight;
      finalRect[3] = y2;
      break;
    case 'bottom-left':
      finalRect[0] = x1;
      finalRect[2] = x1 + boxWidth;
      finalRect[1] = y1;
      finalRect[3] = y1 + boxHeight;
      break;
    case 'bottom-right':
      finalRect[0] = x2 - boxWidth;
      finalRect[2] = x2;
      finalRect[1] = y1;
      finalRect[3] = y1 + boxHeight;
      break;
    case 'top-left':
    default:
      finalRect[0] = x1;
      finalRect[2] = x1 + boxWidth;
      finalRect[1] = y2 - boxHeight;
      finalRect[3] = y2;
      break;
  }

  // Create placeholder with proper PDF structure
  const pdfDoc2 = await PDFDocument.load(pdfInputBytes, {
    updateMetadata: false,
    ignoreEncryption: true,
    addDefaultPage: false,
    preservePDFForm: true
  });

  // Add placeholder with proper structure
  pdflibAddPlaceholder({
    pdfDoc: pdfDoc2,
    reason: String(reason || ''),
    contactInfo: '',
    location: '',
    name: String(userName || ''),
    signingTime,
    signatureLength: 32768,
    widgetRect: finalRect,
    preservePDFForm: true,
    addDefaultPage: false
  });

  // Draw signature text and create appearance stream
  try {
    const context = pdfDoc2.context;
    const acroForm = pdfDoc2.catalog.lookup(PDFName.of('AcroForm'));
    const fields = acroForm.lookup(PDFName.of('Fields'));
    const widget = context.lookup(fields.get(fields.size() - 1));

    // Ensure proper widget structure
    widget.set(PDFName.of('Type'), PDFName.of('Annot'));
    widget.set(PDFName.of('Subtype'), PDFName.of('Widget'));
    widget.set(PDFName.of('FT'), PDFName.of('Sig'));
    widget.set(PDFName.of('F'), PDFNumber.of(132));

    // Draw text on pages
    const [fx1, fy1, fx2, fy2] = finalRect;

    const drawTextOnPage = (page) => {
      // Draw white background
      page.drawRectangle({
        x: fx1,
        y: fy1,
        width: fx2 - fx1,
        height: fy2 - fy1,
        color: rgb(1, 1, 1),
        opacity: 0.85,
        borderWidth: 0
      });

      // Draw text
      const yTop = fy1 + (fy2 - fy1) - padY - fontSize;
      page.drawText(line1, {
        x: fx1 + padX,
        y: yTop,
        size: fontSize,
        font: helv,
        color: rgb(0, 0, 0)
      });

      page.drawText(line2, {
        x: fx1 + padX,
        y: Math.max(0, yTop - lineSpacing),
        size: fontSize,
        font: helv,
        color: rgb(0, 0, 0)
      });
    };

    // Draw on target page
    drawTextOnPage(pdfDoc2.getPages()[targetIndex]);

    // Draw on other pages if requested
    if (stampAllPages) {
      for (let i = 0; i < pageCount; i++) {
        if (i === targetIndex) continue;
        drawTextOnPage(pdfDoc2.getPages()[i]);
      }
    }

    // Create appearance stream
    const esc = (s) => String(s).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
    const apContent = `
      q
      1 1 1 rg
      0 0 ${boxWidth} ${boxHeight} re
      f
      0 0 0 rg
      BT
      /F1 ${fontSize} Tf
      ${padX} ${Math.max(0, boxHeight - padY - fontSize)} Td
      (${esc(line1)}) Tj
      0 ${-lineSpacing} Td
      (${esc(line2)}) Tj
      ET
      Q`.replace(/\s+/g, ' ').trim();

    const apStream = context.stream(apContent, {
      Type: 'XObject',
      Subtype: 'Form',
      BBox: [0, 0, boxWidth, boxHeight],
      Matrix: [1, 0, 0, 1, 0, 0],
      Resources: { 
        Font: { F1: helv.ref },
        ProcSet: ['PDF', 'Text']
      }
    });

    widget.set(PDFName.of('AP'), context.obj({ N: context.register(apStream) }));

  } catch (e) {
    console.warn('Failed to create widget appearance stream:', e);
  }

  return await pdfDoc2.save({ 
    useObjectStreams: false,
    addDefaultPage: false,
    preservePDFForm: true,
    updateMetadata: false
  });
}

// Unified signing flow used by /sign/pdf, /sign/pdf-resign, and /sign/pdf-batch
async function signWithUnifiedFlow(inputBuf, body, dll, pin) {
  const reason = (body && body.reason) || 'Signed via DSC Agent';
  const includeESS = body && body.includeESS !== undefined ? !!body.includeESS : true;
  const embedIntermediates = body && body.embedIntermediates !== undefined ? !!body.embedIntermediates : false;
  const signingTime = parseLocalTime(body && body.signingTime);
  const stampAllPages = !!(body && body.stampAllPages === true);
  let rectOverride = (body && Array.isArray(body.rect) && (body.rect.length === 4 || body.rect.length === 2)) ? body.rect.map((n) => parseInt(n,10)) : null;
  let rectMode = (body && typeof body.rectMode === 'string') ? String(body.rectMode).toLowerCase() : 'pdf';
  // Support x,y (or left,top) when rect is not provided
  try {
    if (!rectOverride) {
      const leftFallback = req.body ? (req.body.left ?? req.body.x) : undefined;
      const topFallback = req.body ? (req.body.top ?? req.body.y) : undefined;
      if (leftFallback !== undefined && topFallback !== undefined) {
        const leftNum = Number(leftFallback);
        const topNum = Number(topFallback);
        if (Number.isFinite(leftNum) && Number.isFinite(topNum)) {
          rectOverride = [leftNum, topNum];
          rectMode = 'top-left';
        }
      }
    }
    if (!rectOverride && body) {
      const xRaw = body.x !== undefined ? body.x : body.left;
      const yRaw = body.y !== undefined ? body.y : body.top;
      const left = Number.parseFloat(xRaw);
      const top = Number.parseFloat(yRaw);
      if (Number.isFinite(left) && Number.isFinite(top)) {
        rectOverride = [Math.round(left), Math.round(top)];
        rectMode = 'top-left';
      }
    }
  } catch {}
  const anchor = (body && typeof body.anchor === 'string') ? String(body.anchor).toLowerCase() : 'top-left';
  const requestedPageIndex = normalizeRequestedPageIndex(body && body.page);

  const { certDER } = detectSigningKey(dll, pin);
  const asn = asn1js.fromBER(ab(certDER));
  const signerCert = new pkijs.Certificate({ schema: asn.result });
  const intermediates = await fetchIntermediatesIfRequested(signerCert, embedIntermediates);
  const userName = signerCert.subject.typesAndValues.find(tv => tv.type === '2.5.4.3')?.value.valueBlock.value || 'Unknown';

  const prepared = await buildPlaceholderWithVisibleStamp(
    inputBuf,
    userName,
    reason,
    signingTime,
    rectOverride,
    rectMode,
    anchor,
    requestedPageIndex,
    stampAllPages,
  );

  const signer = new TokenSigner({ dll, pin, signerCert, intermediates, includeESS, signingTime });
  const signedPdf = await new SignPdf().sign(prepared, signer);
  return signedPdf;
}
// ------- LTV (OCSP) scaffold -------
function findIssuerCert(signerCert, candidates) {
  if (!Array.isArray(candidates)) return null;
  for (const c of candidates) { try { if (signerCert.issuer.isEqual(c.subject)) return c; } catch {} }
  return null;
}

function buildOcspRequestDER(signerCert, issuerCert) {
  try {
    const sha1 = (buf) => crypto.createHash('sha1').update(buf).digest();
    const issuerNameDER = Buffer.from(issuerCert.subject.toSchema().toBER(false));
    const spki = issuerCert.subjectPublicKeyInfo;
    const spkBits = Buffer.from(ab(spki.subjectPublicKey.valueBlock.valueHex)).subarray(1);
    const issuerNameHash = sha1(issuerNameDER);
    const issuerKeyHash = sha1(spkBits);
    const serialHex = Buffer.from(signerCert.serialNumber.valueBlock.valueHex);

    const certID = new asn1js.Sequence({ value: [
      new asn1js.Sequence({ value: [ new asn1js.ObjectIdentifier({ value: OID.sha1 }), new asn1js.Null() ] }),
      new asn1js.OctetString({ valueHex: ab(issuerNameHash) }),
      new asn1js.OctetString({ valueHex: ab(issuerKeyHash) }),
      new asn1js.Integer({ valueHex: ab(serialHex) }),
    ]});
    const request = new asn1js.Sequence({ value: [ certID ] });
    const requestList = new asn1js.Sequence({ value: [ request ] });
    const tbs = new asn1js.Sequence({ value: [ requestList ] });
    const ocspReq = new asn1js.Sequence({ value: [ tbs ] });
    return Buffer.from(ocspReq.toBER(false));
  } catch { return null; }
}

async function httpPostRaw(url, body, contentType) {
  const mod = url.startsWith('https:') ? https : http;
  return await new Promise((resolve, reject) => {
    try {
      const u = new URL(url);
      const req = mod.request({
        method: 'POST', hostname: u.hostname, port: u.port || (u.protocol==='https:'?443:80), path: u.pathname + (u.search||''),
        headers: { 'Content-Type': contentType, 'Accept': 'application/ocsp-response', 'Content-Length': body.length }
      }, (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return resolve(httpPostRaw(res.headers.location, body, contentType));
        }
        if (res.statusCode !== 200) return reject(new Error(`OCSP POST ${url} -> HTTP ${res.statusCode}`));
        const chunks = []; res.on('data', d => chunks.push(d)); res.on('end', () => resolve(Buffer.concat(chunks)));
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    } catch (e) { reject(e); }
  });
}

async function httpGetRawLTV(url) {
  const mod = url.startsWith('https:') ? https : http;
  return new Promise((resolve, reject) => {
    try {
      const req = mod.get(url, (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return resolve(httpGetRawLTV(res.headers.location));
        }
        if (res.statusCode !== 200) return reject(new Error(`GET ${url} -> HTTP ${res.statusCode}`));
        const chunks = []; res.on('data', d => chunks.push(d)); res.on('end', () => resolve(Buffer.concat(chunks)));
      });
      req.on('error', reject); req.end();
    } catch (e) { reject(e); }
  });
}

function getCRLUrlsFromCert(cert) {
  const out = [];
  try {
    const OID_CRL = OID.crlDistPoints;
    const ext = (cert.extensions || []).find((e) => e.extnID === OID_CRL);
    if (!ext) return out;
    const inner = asn1js.fromBER(ext.extnValue.valueBlock.valueHex).result;
    if (!inner || inner.constructor.name !== 'Sequence') return out;
    for (const dp of inner.valueBlock.value) {
      try {
        const dpn = dp.valueBlock.value[0];
        if (!dpn) continue;
        const fullName = dpn.valueBlock.value[0];
        if (!fullName || !fullName.valueBlock || !fullName.valueBlock.value) continue;
        for (const gn of fullName.valueBlock.value) {
          if (gn.idBlock.tagClass === 3 && gn.idBlock.tagNumber === 6) {
            const uri = Buffer.from(gn.valueBlock.valueHex).toString('ascii').trim();
            if (uri) out.push(uri);
          }
        }
      } catch {}
    }
  } catch {}
  return out;
}

async function buildRevocationInfoUnsignedAttr(signerCert, intermediates) {
  try {
    const urls = pdfUtil.getAIAUrls(signerCert);
    const ocsp = urls && urls.ocsp ? urls.ocsp : [];
    const crls = getCRLUrlsFromCert(signerCert);
    const issuer = findIssuerCert(signerCert, intermediates);
    if (!issuer) return null;

    // OCSP
    let ocspResp = null;
    if (ocsp.length) {
      const reqDer = buildOcspRequestDER(signerCert, issuer);
      if (reqDer) {
        for (const url of ocsp) {
          try { ocspResp = await httpPostRaw(url, reqDer, 'application/ocsp-request'); if (ocspResp && ocspResp.length) break; } catch {}
        }
      }
    }

    // CRL
    const crlBlobs = [];
    for (const url of crls) {
      try { const buf = await httpGetRawLTV(url); if (buf && buf.length) crlBlobs.push(buf); } catch {}
    }

    if (!ocspResp && crlBlobs.length === 0) return null;

    const values = [];
    if (crlBlobs.length) {
      const crlSeq = new asn1js.Sequence({ value: crlBlobs.map((b) => new asn1js.OctetString({ valueHex: ab(b) })) });
      const crlTagged = new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0, isConstructed: true }, value: [ crlSeq ] });
      values.push(crlTagged);
    }
    if (ocspResp) {
      const ocspSeq = new asn1js.Sequence({ value: [ new asn1js.OctetString({ valueHex: ab(ocspResp) }) ] });
      const ocspTagged = new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 1, isConstructed: true }, value: [ ocspSeq ] });
      values.push(ocspTagged);
    }
    const top = new asn1js.Sequence({ value: values });
    return new pkijs.Attribute({ type: OID.adbeRevInfoArchival, values: [ top ] });
  } catch { return null; }
}

function extractBasicOcspResponse(ocspRespBuf) {
  try {
    const asn = asn1js.fromBER(ab(ocspRespBuf));
    const root = asn.result; // OCSPResponse
    // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }
    if (!root || root.constructor.name !== 'Sequence') return null;
    const rb = root.valueBlock.value.find(v => v.idBlock && v.idBlock.tagClass === 3 && v.idBlock.tagNumber === 0);
    if (!rb || !rb.value || !rb.value.length) return null;
    const responseBytes = rb.value[0];
    if (!responseBytes || responseBytes.constructor.name !== 'Sequence') return null;
    const oid = responseBytes.valueBlock.value[0];
    const oct = responseBytes.valueBlock.value[1];
    if (!oid || !oct) return null;
    const oidStr = oid.valueBlock.toString();
    if (oidStr !== OID.ocspBasic) return null;
    const basicDER = Buffer.from(oct.valueBlock.valueHex);
    const parsed = asn1js.fromBER(ab(basicDER));
    return parsed.result || null; // BasicOCSPResponse (asn1js object)
  } catch { return null; }
}

async function buildEtsiRevocationValuesUnsignedAttr(signerCert, intermediates) {
  try {
    const urls = pdfUtil.getAIAUrls(signerCert);
    const ocsp = urls && urls.ocsp ? urls.ocsp : [];
    const crls = getCRLUrlsFromCert(signerCert);
    const issuer = findIssuerCert(signerCert, intermediates);
    if (!issuer) return null;

    // OCSP basic response
    let basicRespAsn1 = null;
    if (ocsp.length) {
      const reqDer = buildOcspRequestDER(signerCert, issuer);
      if (reqDer) {
        for (const url of ocsp) {
          try {
            const resp = await httpPostRaw(url, reqDer, 'application/ocsp-request');
            const basic = extractBasicOcspResponse(resp);
            if (basic) { basicRespAsn1 = basic; break; }
          } catch {}
        }
      }
    }

    // CRLs as DER
    const crlSeqValues = [];
    for (const url of crls) {
      try {
        let buf = await httpGetRawLTV(url);
        const s = buf.toString('utf8');
        if (/-----BEGIN/i.test(s)) {
          const b64 = s.replace(/-----(BEGIN|END)[^-]*-----/g, '').replace(/[\\r\\n\s]/g, '');
          buf = Buffer.from(b64, 'base64');
        }
        const asn = asn1js.fromBER(ab(buf));
        if (asn.result) crlSeqValues.push(asn.result);
      } catch {}
    }

    if (!basicRespAsn1 && crlSeqValues.length === 0) return null;

    const values = [];
    if (crlSeqValues.length) {
      const crlVals = new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0, isConstructed: true }, value: [ new asn1js.Sequence({ value: crlSeqValues }) ] });
      values.push(crlVals);
    }
    if (basicRespAsn1) {
      const ocspVals = new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 1, isConstructed: true }, value: [ new asn1js.Sequence({ value: [ basicRespAsn1 ] }) ] });
      values.push(ocspVals);
    }
    const revVals = new asn1js.Sequence({ value: values });
    return new pkijs.Attribute({ type: '1.2.840.113549.1.9.16.2.24', values: [ revVals ] });
  } catch { return null; }
}

// -------------- HTTP service --------------
const app = express();
app.use(express.json({ limit: `${MAX_BODY_MB}mb` }));
app.use(cors);

let picked = null;
function resolveByUserSelection() {
  if (USER_SELECTED_DLL) {
    try { return pkcs11lib.pickModule(USER_SELECTED_DLL); } catch (e) { throw e; }
  }
  if (USER_SELECTED_TOKEN) {
    const candidates = pkcs11lib.getKnownTokenCandidates(USER_SELECTED_TOKEN);
    if (!candidates.length) throw new Error('Unknown token selection');
    return pkcs11lib.pickFromCandidates(candidates);
  }
  return null;
}
function ensureDllPicked() {
  if (!picked) {
    let sel = null;
    try { sel = resolveByUserSelection(); } catch {}
    picked = sel || pickModule();
  }
  return picked;
}

app.get('/health', (req, res) => {
  try { const { dll, slotPresent } = ensureDllPicked(); res.json({ ok:true, version: VERSION, dll, slotPresent, requirePinPerSign: REQUIRE_PIN_PER_SIGN, promptAvailable: !!PIN_PROMPT_URL }); }
  catch(e){ res.status(500).json({ ok:false, message: e.message }); }
});

// List known tokens and current selection
app.get('/tokens', requireAuth, (req, res) => {
  try {
    const map = cfg.KNOWN_TOKENS || {};
    const fs = require('fs');
    const tokens = Object.keys(map).map((name) => ({
      name,
      candidates: (map[name].paths || []).map((p) => ({ path: p, exists: fs.existsSync(p) })),
    }));
    res.json({ ok: true, selected: { tokenName: USER_SELECTED_TOKEN, dll: USER_SELECTED_DLL }, tokens });
  } catch (e) {
    res.status(500).json({ ok:false, message: e.message });
  }
});

// Select token by name or explicit DLL path
// Body: { tokenName?: string, dll?: string }
app.post('/token/select', requireAuth, (req, res) => {
  try {
    const body = req.body || {};
    const fs = require('fs');
    const tname = typeof body.tokenName === 'string' ? body.tokenName : '';
    const dllIn = typeof body.dll === 'string' ? body.dll : '';
    let selected = null;
    if (dllIn) {
      if (!fs.existsSync(dllIn)) return res.status(400).json({ ok:false, message: 'DLL not found' });
      selected = pkcs11lib.pickModule(dllIn);
      USER_SELECTED_DLL = selected.dll;
      USER_SELECTED_TOKEN = '';
    } else if (tname) {
      const candidates = pkcs11lib.getKnownTokenCandidates(tname);
      if (!candidates.length) return res.status(400).json({ ok:false, message: 'Unknown tokenName' });
      selected = pkcs11lib.pickFromCandidates(candidates);
      USER_SELECTED_DLL = selected.dll;
      USER_SELECTED_TOKEN = tname;
    } else {
      return res.status(400).json({ ok:false, message: 'Provide tokenName or dll' });
    }
    picked = selected; // reset/replace cached pick
    res.json({ ok:true, dll: selected.dll, slotPresent: !!selected.slotPresent, tokenName: USER_SELECTED_TOKEN });
  } catch (e) {
    res.status(500).json({ ok:false, message: e.message });
  }
});

// Clear any user selection
app.post('/token/clear', requireAuth, (req, res) => {
  USER_SELECTED_DLL = '';
  USER_SELECTED_TOKEN = '';
  picked = null;
  res.json({ ok:true });
});

app.get('/certs', requireAuth, (req, res) => {
  try {
    const { dll } = ensureDllPicked();
    const pin = DSC_PIN_ENV || '';
    const pairs = pkcs11lib.listPairs(dll, pin);
    res.json({ ok:true, pairs });
  } catch(e) { res.status(500).json({ ok:false, message: e.message }); }
});



// Append a new signature to an already-signed PDF (multi-signer scenario)
// Does not modify existing signatures; performs an incremental update.
// POST /sign/pdf-append
// Body: { pdfBase64, reason?, includeESS?, embedIntermediates?, signingTime?, pin?, requirePin?, rememberSessionPin?, rect?, anchor? }
// Returns: { ok: true, signedPdfBase64 }

// (removed) /sign/pdf-resign-flatten-old alias
app.post('/sign/pdf', requireAuth, async (req, res) => {
  try {
    const { dll } = ensureDllPicked();

    // PIN handling (unchanged)
    let pin = (req.body && req.body.pin) || DSC_PIN_ENV || '';
    if (!pin && SESSION_PIN) pin = SESSION_PIN;
    let requirePin = (req.body && req.body.requirePin === true) || REQUIRE_PIN_PER_SIGN;
    if (SESSION_PIN && !(req.body && req.body.requirePin === true)) {
      requirePin = false;
    }
    if (requirePin) {
      try {
        pin = await promptPinInteractive('Enter token PIN to sign');
        if (req.body && req.body.rememberSessionPin === true && pin) {
          SESSION_PIN = String(pin);
        }
      } catch (e) {
        return res.status(400).json({ ok: false, message: e.message || 'PIN required' });
      }
    }
    if (req.body && req.body.rememberSessionPin === false) {
      SESSION_PIN = '';
    }

    // Input validation
    const b64 = req.body && req.body.pdfBase64;
    if (!b64) return res.status(400).json({ ok: false, message: 'pdfBase64 missing' });

    // Parse parameters
    const reason = (req.body && req.body.reason) || 'Signed via DSC Agent';
    const includeESS = req.body && req.body.includeESS !== undefined ? !!req.body.includeESS : true;
    const embedIntermediates = req.body && req.body.embedIntermediates !== undefined ? !!req.body.embedIntermediates : false;
    const signingTime = parseLocalTime(req.body && req.body.signingTime);
    const stampAllPages = !!(req.body && req.body.stampAllPages === true);

    // Rectangle handling
    let rectOverride = (req.body && Array.isArray(req.body.rect) && (req.body.rect.length === 4 || req.body.rect.length === 2)) 
      ? req.body.rect.map((n) => parseInt(n, 10)) 
      : null;
    let rectMode = (req.body && typeof req.body.rectMode === 'string') 
      ? String(req.body.rectMode).toLowerCase() 
      : 'pdf';

    // Support x,y coordinates
    if (!rectOverride && req.body) {
      const xRaw = req.body.x !== undefined ? req.body.x : req.body.left;
      const yRaw = req.body.y !== undefined ? req.body.y : req.body.top;
      const x = Number.parseFloat(xRaw);
      const y = Number.parseFloat(yRaw);
      if (Number.isFinite(x) && Number.isFinite(y)) {
        rectOverride = [Math.round(x), Math.round(y)];
        rectMode = 'top-left';
      }
    }

    const anchor = (req.body && typeof req.body.anchor === 'string') 
      ? String(req.body.anchor).toLowerCase() 
      : 'top-left';
    const requestedPageIndex = normalizeRequestedPageIndex(req.body && req.body.page);

    // Load and validate input PDF
    const inputBuf = Buffer.from(b64, 'base64');
    assertNoExistingSignature(inputBuf);

    // Detect signing key and prepare certificates
    const { certDER } = detectSigningKey(dll, pin);
    const asn = asn1js.fromBER(ab(certDER));
    const signerCert = new pkijs.Certificate({ schema: asn.result });
    const intermediates = await fetchIntermediatesIfRequested(signerCert, embedIntermediates);
    const userName = signerCert.subject.typesAndValues.find(tv => tv.type === '2.5.4.3')?.value.valueBlock.value || 'Unknown';

    // --- SINGLE PDF LOAD, PLACEHOLDER, AND STAMP ---
    const pdfDoc = await PDFDocument.load(inputBuf, { updateMetadata: false, ignoreEncryption: true });
    const pageCount = pdfDoc.getPageCount();
    const targetIndex = (requestedPageIndex === 'last') ? (pageCount - 1) 
      : (requestedPageIndex && requestedPageIndex > 0 ? Math.min(pageCount - 1, requestedPageIndex - 1) : 0);
    const targetPage = pdfDoc.getPages()[targetIndex];
    const pageSize = targetPage.getSize();

    // Calculate text and box
    const helv = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const fontSize = 10, lineSpacing = 14, padX = 6, padY = 6;
    const pad = (n) => String(n).padStart(2, '0');
    const dt = signingTime || new Date();
    const tsText = `${dt.getFullYear()}-${pad(dt.getMonth()+1)}-${pad(dt.getDate())} ${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`;
    const line1 = `Digitally signed by ${userName}`;
    const line2 = `Date: ${tsText}`;
    const line1Width = helv.widthOfTextAtSize(line1, fontSize);
    const line2Width = helv.widthOfTextAtSize(line2, fontSize);
    const textWidth = Math.max(line1Width, line2Width);
    const textHeight = (2 * fontSize) + (lineSpacing - fontSize);
    const boxWidth = Math.ceil(textWidth) + (padX * 2);
    const boxHeight = textHeight + (padY * 2);

    // Calculate rectangle
    let x1, y1, x2, y2;
    if (rectOverride) {
      if (rectMode === 'top-left') {
        const left = Number(rectOverride[0]) || 0;
        const top = Number(rectOverride[1]) || 0;
        x1 = Math.max(0, Math.min(pageSize.width - boxWidth, left));
        y2 = Math.max(boxHeight, Math.min(pageSize.height, pageSize.height - top));
        x2 = x1 + boxWidth;
        y1 = y2 - boxHeight;
      } else {
        [x1, y1, x2, y2] = rectOverride;
        if (x2 - x1 < boxWidth) x2 = x1 + boxWidth;
        if (y2 - y1 < boxHeight) y2 = y1 + boxHeight;
      }
    } else {
      [x1, y1, x2, y2] = SIGN_RECT;
    }
    x1 = Math.max(0, Math.min(pageSize.width - boxWidth, x1));
    x2 = Math.min(pageSize.width, x1 + boxWidth);
    y1 = Math.max(0, y1);
    y2 = Math.min(pageSize.height, Math.max(y1 + boxHeight, y2));
    const finalRect = [x1, y1, x2, y2];

    // Add placeholder
    pdflibAddPlaceholder({
      pdfDoc,
      reason: String(reason || ''),
      contactInfo: '',
      location: '',
      name: String(userName || ''),
      signingTime,
      signatureLength: 32768,
      widgetRect: finalRect,
    });

    // Find the widget
    const context = pdfDoc.context;
    const acroForm = pdfDoc.catalog.lookup(PDFName.of('AcroForm'));
    const fields = acroForm.lookup(PDFName.of('Fields'));
    const widget = context.lookup(fields.get(fields.size() - 1));

    // Update widget rect
    widget.set(PDFName.of('Rect'), context.obj(finalRect));

    // Draw visible stamp on page
    // const [fx1, fy1, fx2, fy2] = finalRect;
    // const yTop = fy1 + (fy2 - fy1) - padY - fontSize;
    // targetPage.drawRectangle({
    //   x: fx1,
    //   y: fy1,
    //   width: fx2 - fx1,
    //   height: fy2 - fy1,
    //   color: rgb(1, 1, 1),
    //   opacity: 0.85,
    //   borderWidth: 0
    // });
    // targetPage.drawText(line1, {
    //   x: fx1 + padX,
    //   y: yTop,
    //   size: fontSize,
    //   font: helv,
    //   color: rgb(0, 0, 0)
    // });
    // targetPage.drawText(line2, {
    //   x: fx1 + padX,
    //   y: Math.max(0, yTop - lineSpacing),
    //   size: fontSize,
    //   font: helv,
    //   color: rgb(0, 0, 0)
    // });

    // Appearance stream for widget
    try {
      const esc = (s) => String(s).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
      const apContent = [
        'BT',
        `/F1 ${fontSize} Tf`,
        `1 0 0 1 ${padX} ${Math.max(0, boxHeight - padY - fontSize)} Tm`,
        `(${esc(line1)}) Tj`,
        `1 0 0 1 ${padX} ${Math.max(0, boxHeight - padY - fontSize - lineSpacing)} Tm`,
        `(${esc(line2)}) Tj`,
        'ET'
      ].join('\n');
      const apStream = context.stream(apContent, {
        Type: 'XObject',
        Subtype: 'Form',
        BBox: [0, 0, boxWidth, boxHeight],
        Matrix: [1, 0, 0, 1, 0, 0],
        Resources: { Font: { F1: helv.ref } }
      });
      widget.set(PDFName.of('AP'), context.obj({ N: context.register(apStream) }));
    } catch (e) {
      console.warn('Failed to create widget appearance stream:', e);
    }

    // Save PDF
    const pdfWithPlaceholder = await pdfDoc.save({ useObjectStreams: false });

    // Sign the PDF
    const signer = new TokenSigner({ 
      dll, 
      pin, 
      signerCert, 
      intermediates, 
      includeESS, 
      signingTime 
    });
    const signedPdf = await new SignPdf().sign(pdfWithPlaceholder, signer);

    res.json({ 
      ok: true, 
      signedPdfBase64: signedPdf.toString('base64') 
    });

  } catch (e) {
    console.error('PDF signing failed:', e);
    res.status(500).json({ 
      ok: false, 
      message: e.message || 'PDF signing failed' 
    });
  }
});
app.post('/sign/pdf-resign-flatten', requireAuth, async (req, res) => {
  try {
    const { dll } = ensureDllPicked();

    // PIN resolution (reuse session PIN if present)
    let pin = (req.body && req.body.pin) || DSC_PIN_ENV || '';
    if (!pin && SESSION_PIN) pin = SESSION_PIN;
    let requirePin = (req.body && req.body.requirePin === true) || REQUIRE_PIN_PER_SIGN;
    if (SESSION_PIN && !(req.body && req.body.requirePin === true)) {
      requirePin = false;
    }
    if (requirePin) {
      try {
        pin = await promptPinInteractive('Enter token PIN to sign (flatten)');
        if (req.body && req.body.rememberSessionPin === true && pin) {
          SESSION_PIN = String(pin);
        }
      } catch (e) {
        return res.status(400).json({ ok: false, message: e.message || 'PIN required' });
      }
    }
    if (req.body && req.body.rememberSessionPin === false) {
      SESSION_PIN = '';
    }

    const b64 = req.body && req.body.pdfBase64;
    if (!b64) return res.status(400).json({ ok:false, message: 'pdfBase64 missing' });

    const reason = (req.body && req.body.reason) || 'Signed via DSC Agent';
    const includeESS = req.body && req.body.includeESS !== undefined ? !!req.body.includeESS : true;
    const embedIntermediates = req.body && req.body.embedIntermediates !== undefined ? !!req.body.embedIntermediates : false;
    const signingTime = parseLocalTime(req.body && req.body.signingTime);
    const useViewerAppearance = !!(req.body && req.body.useViewerAppearance === true);
    const stampPrevious = !!(req.body && req.body.stampPrevious === true);
    // Accept rect as [x1,y1,x2,y2] or top-left as [left, top]
    const rectOverride = (req.body && Array.isArray(req.body.rect) && (req.body.rect.length === 4 || req.body.rect.length === 2))
      ? req.body.rect.map((n) => parseInt(n, 10))
      : null;
    let rectMode = (req.body && typeof req.body.rectMode === 'string') ? String(req.body.rectMode).toLowerCase() : 'top-left';
    const debugRect = !!(req.body && req.body.debugRect === true);
    const anchor = (req.body && typeof req.body.anchor === 'string') ? String(req.body.anchor).toLowerCase() : 'top-left';
    const pageReq = req.body && req.body.page;
    const requestedPageIndex = normalizeRequestedPageIndex(pageReq);

    const inputBuf = Buffer.from(b64, 'base64');

    // Extract previous signature widget positions for stamping
    const prevBoxes = await extractPreviousSignerLines(inputBuf);

    // Build a fresh PDF by copying page content only
    let flattenedBuf;
    try {
      const srcDoc = await safeLoadPdf(inputBuf);
      const dstDoc = await PDFDocument.create();
      const pageCount = srcDoc.getPageCount();
      const indices = Array.from({ length: pageCount }, (_, i) => i);
      const copied = await dstDoc.copyPages(srcDoc, indices);
      for (const p of copied) {
        // Ensure page has no Annots
        try { p.node.set(PDFName.of('Annots'), dstDoc.context.obj([])); } catch {}
        dstDoc.addPage(p);
      }
      try { const perms = dstDoc.catalog.lookupMaybe ? dstDoc.catalog.lookupMaybe(PDFName.of('Perms')) : null; if (perms && perms.delete) perms.delete(PDFName.of('DocMDP')); } catch {}
      try { if (dstDoc.catalog.delete) dstDoc.catalog.delete(PDFName.of('AcroForm')); } catch {}

      // Redraw previous signer text (opt-in)
      if (stampPrevious && Array.isArray(prevBoxes) && prevBoxes.length) {
        const helv = await dstDoc.embedFont(StandardFonts.Helvetica);
        const padX = 6, padY = 6; const fontSize = 10; const lh = 14;
        const fit = (t, maxW) => { let s = String(t||''); while (helv.widthOfTextAtSize(s, fontSize) > maxW && s.length > 1) s = s.slice(0,-1); return s; };
        const fmt = (mstr) => { try { const m = /(?:D:)?(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?/.exec(mstr || ''); if (!m) return ''; const [, y, mo, d, h, mi, se='00'] = m; return `${y}-${mo}-${d} ${h}:${mi}:${se}`; } catch { return ''; } };
        for (const box of prevBoxes) {
          const idx = Math.max(0, Math.min(dstDoc.getPageCount()-1, box.pageIndex || 0));
          const page = dstDoc.getPage(idx);
          const [x1, y1, x2, y2] = box.rect.map(n => Number(n)||0);
          const maxW = Math.max(0, (Math.max(0, x2 - x1) - padX*2));
          const nameLine = `Digitally signed by ${box.name || 'Unknown'}`;
          const dateLine = box.when ? `Date: ${fmt(box.when)}` : '';
          const line1Fit = fit(nameLine, maxW);
          const line2Fit = fit(dateLine, maxW);
          page.drawText(line1Fit, { x: x1 + padX, y: y1 + Math.max(0, (y2 - y1) - padY - fontSize), size: fontSize, font: helv });
          if (line2Fit) page.drawText(line2Fit, { x: x1 + padX, y: y1 + Math.max(0, (y2 - y1) - padY - fontSize - lh), size: fontSize, font: helv });
        }
      }

      flattenedBuf = await dstDoc.save({ useObjectStreams: false });
    } catch (e) {
      return res.status(400).json({ ok:false, message: 'Flatten failed: ' + (e.message || String(e)) });
    }

    // Prepare for placeholder
    // If we rely on the viewer to render appearances, set NeedAppearances=true.
    // Otherwise, avoid setting it so our custom AP shows immediately in all viewers.
    let pdfForPlaceholder = flattenedBuf;
    try {
      const pdfDoc = await safeLoadPdf(flattenedBuf);
      if (useViewerAppearance) {
        try { pdfDoc.catalog.set(PDFName.of('NeedAppearances'), pdfDoc.context.obj(true)); } catch {}
      } else {
        try { if (pdfDoc.catalog.delete) pdfDoc.catalog.delete(PDFName.of('NeedAppearances')); } catch {}
      }
      pdfForPlaceholder = await pdfDoc.save({ useObjectStreams: false });
    } catch {}

    // Detect signer key + chain
    const { idHex, certDER } = detectSigningKey(dll, pin);
    const asn = asn1js.fromBER(ab(certDER));
    const signerCert = new pkijs.Certificate({ schema: asn.result });
    const intermediates = await fetchIntermediatesIfRequested(signerCert, embedIntermediates);
    const userName = signerCert.subject.typesAndValues.find(tv => tv.type === '2.5.4.3')?.value.valueBlock.value || 'Unknown';

    // Compute rectangle relative to target page (like append path uses defaults)
    let placeholderRect = rectOverride || SIGN_RECT;
    try {
      const tmpDoc = await safeLoadPdf(pdfForPlaceholder);
      const pageCountTMP = tmpDoc.getPageCount();
      const targetIndexTMP = (requestedPageIndex === 'last') ? (pageCountTMP - 1) : (Math.max(0, Math.min(pageCountTMP - 1, (requestedPageIndex > 0 ? requestedPageIndex - 1 : 0))));
      const szTMP = tmpDoc.getPages()[targetIndexTMP].getSize();
      // New: accept normalized rectangle from client (nx,ny,nw,nh) in [0..1] relative to page size
      try {
        const rn = (req.body && Array.isArray(req.body.rectNorm) && req.body.rectNorm.length === 4)
          ? req.body.rectNorm.map((v) => Number(v))
          : null;
        if (rn) {
          let [nx, ny, nw, nh] = rn;
          nx = isFinite(nx) ? Math.max(0, Math.min(1, nx)) : 0;
          ny = isFinite(ny) ? Math.max(0, Math.min(1, ny)) : 0;
          nw = isFinite(nw) ? Math.max(0, Math.min(1, nw)) : 0.2;
          nh = isFinite(nh) ? Math.max(0, Math.min(1, nh)) : 0.06;
          const pxW = Math.max(1, Math.round(nw * szTMP.width));
          const pxH = Math.max(1, Math.round(nh * szTMP.height));
          const x1n = Math.round(nx * szTMP.width);
          const y2n = Math.round(szTMP.height - (ny * szTMP.height));
          const x2n = Math.min(szTMP.width, x1n + pxW);
          const y1n = Math.max(0, y2n - pxH);
          placeholderRect = clampRectToPage([x1n, y1n, x2n, y2n], szTMP);
        }
      } catch {}
      if (rectOverride && rectMode === 'top-left') {
        const arr = rectOverride.map(n => Number(n) || 0);
        const L = arr[0] || 0; const T = arr[1] || 0;
        const defW = Math.max(1, Math.min(200, Math.floor(szTMP.width - Math.max(0, L))));
        const defH = Math.max(1, Math.min(50, Math.floor(szTMP.height - Math.max(0, T))));
        const Wd = (arr.length >= 3 && Number.isFinite(arr[2])) ? Math.max(1, arr[2]) : defW;
        const Ht = (arr.length >= 4 && Number.isFinite(arr[3])) ? Math.max(1, arr[3]) : defH;
        const x1 = Math.max(0, L);
        const y2 = Math.max(0, szTMP.height - T);
        const x2 = Math.min(szTMP.width, x1 + Wd);
        const y1 = Math.max(0, y2 - Ht);
        placeholderRect = clampRectToPage([x1, y1, x2, y2], szTMP);
      } else if (Array.isArray(placeholderRect)) {
        placeholderRect = clampRectToPage(placeholderRect, szTMP);
      }

      // If client sent rectNorm, do not auto-shift later; otherwise allow simple stacking
      const hasRectNorm = !!(req.body && Array.isArray(req.body.rectNorm) && req.body.rectNorm.length === 4);

      // Avoid overlapping prior signature boxes on target page
      try {
        const pageIdx = targetIndexTMP;
        const onPage = Array.isArray(prevBoxes) ? prevBoxes.filter(b => (b.pageIndex|0) === pageIdx) : [];
        const overlap = (a,b) => !(a[2] <= b[0] || a[0] >= b[2] || a[3] <= b[1] || a[1] >= b[3]);
        const anyOverlap = (r) => onPage.some(b => overlap(r, b.rect.map(n=>Number(n)||0)));
        let w = Math.max(1, placeholderRect[2]-placeholderRect[0]);
        let h = Math.max(1, placeholderRect[3]-placeholderRect[1]);
        const tryRect = (x1,y1) => clampRectToPage([x1, y1, x1+w, y1+h], szTMP);
        const skipReposition = hasRectNorm; // user rectangle => no auto-move
        if (!skipReposition && anyOverlap(placeholderRect)) {
          const gap = 12; const margin = 24;
          let x1 = placeholderRect[0]; let y1 = placeholderRect[1];
          // Stack downward below existing boxes
          let tries = 0; const maxTries = 200;
          while (tries++ < maxTries && anyOverlap([x1, y1, x1 + w, y1 + h])) {
            y1 = y1 + h + gap;
            if (y1 + h + margin > szTMP.height) { // overflow, move near top-left margin area
              y1 = Math.max(margin, szTMP.height - h - margin);
              x1 = margin;
            }
          }
          placeholderRect = clampRectToPage([x1, y1, x1 + w, y1 + h], szTMP);
        }
      } catch {}
    } catch {}

    // Pre-stamp the visible text into page content before creating the placeholder,
    // so the stamp is present even if a viewer ignores the widget AP on first load.
    try {
      const docStamp = await safeLoadPdf(pdfForPlaceholder);
      const pageCountS = docStamp.getPageCount();
      const targetIndexS = (requestedPageIndex === 'last') ? (pageCountS - 1) : (Math.max(0, Math.min(pageCountS - 1, (requestedPageIndex > 0 ? requestedPageIndex - 1 : 0))));
      const pageS = docStamp.getPages()[targetIndexS];
      const [x1s, y1s, x2s, y2s] = placeholderRect;
      const helvS = await docStamp.embedFont(StandardFonts.Helvetica);
      const padS = (n)=>String(n).padStart(2,'0');
      const dtS = signingTime || new Date();
      const tsTextS = `${dtS.getFullYear()}-${padS(dtS.getMonth()+1)}-${padS(dtS.getDate())} ${padS(dtS.getHours())}:${padS(dtS.getMinutes())}:${padS(dtS.getSeconds())}`;
      const line1S = `Digitally signed by ${userName}`;
      const line2S = `Date: ${tsTextS}`;
      const fontSizeS = 10, lhS = 14; const padXS=6, padYS=6;
      const fitTextS=(t,maxW)=>{ let s=String(t||''); while(helvS.widthOfTextAtSize(s,fontSizeS)>maxW && s.length>1) s=s.slice(0,-1); return s; };
      const maxTextWS = Math.max(0, (Math.max(0,x2s-x1s) - padXS*2));
      const line1FitS = fitTextS(line1S, maxTextWS);
      const line2FitS = fitTextS(line2S, maxTextWS);
      // Compute minimal background box to fit the two lines
      const contentW = Math.max(helvS.widthOfTextAtSize(line1FitS, fontSizeS), helvS.widthOfTextAtSize(line2FitS, fontSizeS));
      const wBox = Math.min(Math.max(0, x2s - x1s), Math.ceil(contentW) + padXS*2);
      const hBox = Math.min(Math.max(0, y2s - y1s), (2*fontSizeS) + (lhS - fontSizeS) + padYS*2);
      // Anchor at left-bottom of the placeholder rect
      const bx1 = x1s;
      const by1 = y1s;
      try { pageS.drawRectangle({ x: bx1, y: by1, width: Math.max(1,wBox), height: Math.max(1,hBox), color: rgb(1,1,1), opacity: 1, borderOpacity: 0 }); } catch {}
      try {
        const yTop = by1 + Math.max(0, hBox - padYS - fontSizeS);
        pageS.drawText(line1FitS, { x: bx1 + padXS, y: yTop, size: fontSizeS, font: helvS, color: rgb(0,0,0) });
        if (line2FitS) pageS.drawText(line2FitS, { x: bx1 + padXS, y: Math.max(0, yTop - lhS), size: fontSizeS, font: helvS, color: rgb(0,0,0) });
      } catch {}
      pdfForPlaceholder = await docStamp.save({ useObjectStreams: false });
    } catch {}

    // Use plainAddPlaceholder, then inject AP/wiring
    let pdfWithPlaceholder = plainAddPlaceholder({ pdfBuffer: Buffer.from(pdfForPlaceholder), reason: String(reason||''), name: String(userName||''), signatureLength: 32768, widgetRect: placeholderRect });

    try {
      const pdfDoc2 = await safeLoadPdf(pdfWithPlaceholder);
      const context = pdfDoc2.context;
      const acroForm = pdfDoc2.catalog.lookup(PDFName.of('AcroForm'));
      const fields = acroForm.lookup(PDFName.of('Fields'));
      const fieldRef = fields.get(fields.size() - 1);
      const field = context.lookup(fieldRef);
      let widgetRef = null; let widget = null;
      try { const kids = field.lookup(PDFName.of('Kids')); widgetRef = kids && (kids.get ? kids.get(0) : (kids.array ? kids.array[0] : null)); if (widgetRef) widget = context.lookup(widgetRef); } catch {}
      if (!widget) { widgetRef = fieldRef; widget = context.lookup(fieldRef); }
      try { field.set(PDFName.of('FT'), PDFName.of('Sig')); } catch {}
      try { const tMaybe = field.lookupMaybe ? field.lookupMaybe(PDFName.of('T')) : null; if (!tMaybe) field.set(PDFName.of('T'), PDFString.of('Signature1')); } catch {}
      try { widget.set(PDFName.of('Type'), PDFName.of('Annot')); } catch {}
      try { widget.set(PDFName.of('Subtype'), PDFName.of('Widget')); } catch {}
      try { widget.set(PDFName.of('F'), PDFNumber.of(4)); } catch {}
      try { widget.set(PDFName.of('Parent'), fieldRef); } catch {}
      // Ensure field lists the widget in /Kids for maximum viewer compatibility
      try {
        let kids = field.lookupMaybe ? field.lookupMaybe(PDFName.of('Kids')) : null;
        if (!kids) {
          field.set(PDFName.of('Kids'), context.obj([ widgetRef ]));
        } else if (kids.push) {
          let present = false;
          try {
            const size = kids.size ? kids.size() : (kids.array ? kids.array.length : 0);
            for (let i = 0; i < size; i++) { const r = kids.get ? kids.get(i) : kids.array[i]; if (r === widgetRef) { present = true; break; } }
          } catch {}
          if (!present) kids.push(widgetRef);
        }
      } catch {}
      try { const acf = pdfDoc2.catalog.lookup(PDFName.of('AcroForm')); acf.set(PDFName.of('SigFlags'), PDFNumber.of(3)); } catch {}
      // Ensure NeedAppearances is off when we inject a custom AP so appearance is visible immediately
      if (!useViewerAppearance) { try { if (pdfDoc2.catalog.delete) pdfDoc2.catalog.delete(PDFName.of('NeedAppearances')); } catch {} }
      // Field owns /V
      try { if (widget.delete) widget.delete(PDFName.of('V')); } catch {}

      const pageCount2 = pdfDoc2.getPageCount();
      const targetIndex2 = (requestedPageIndex === 'last') ? (pageCount2 - 1) : (Math.max(0, Math.min(pageCount2 - 1, (requestedPageIndex > 0 ? requestedPageIndex - 1 : 0))));
      const targetPage2 = pdfDoc2.getPages()[targetIndex2];
      try { widget.set(PDFName.of('P'), targetPage2.ref); } catch {}
      // Force widget rectangle to final placeholderRect to ensure click target is at the new location
      try { const [x1,y1,x2,y2] = placeholderRect; widget.set(PDFName.of('Rect'), context.obj([x1,y1,x2,y2])); } catch {}
      // Also align /AP normal appearance BBox with the rect to prevent visual offset
      try {
        const apDict = widget.lookupMaybe ? widget.lookupMaybe(PDFName.of('AP')) : null;
        if (apDict) {
          const nAp = apDict.lookupMaybe ? apDict.lookupMaybe(PDFName.of('N')) : null;
          if (nAp && nAp.set) {
            const wAp = Math.max(0, placeholderRect[2] - placeholderRect[0]);
            const hAp = Math.max(0, placeholderRect[3] - placeholderRect[1]);
            try { nAp.set(PDFName.of('BBox'), context.obj([0, 0, wAp, hAp])); } catch {}
          }
        }
      } catch {}
      let ann = targetPage2.node.lookupMaybe ? targetPage2.node.lookupMaybe(PDFName.of('Annots')) : null;
      if (!ann) targetPage2.node.set(PDFName.of('Annots'), context.obj([ widgetRef ]));
      else {
        try {
          const existing = [];
          if (ann.size && ann.get) { for (let i = 0; i < ann.size(); i++) existing.push(ann.get(i)); }
          else if (ann.array) { for (const r of ann.array) existing.push(r); }
          let present = false; for (const r of existing) { if (r === widgetRef) { present = true; break; } }
          if (!present) existing.push(widgetRef);
          targetPage2.node.set(PDFName.of('Annots'), context.obj(existing));
        } catch { targetPage2.node.set(PDFName.of('Annots'), context.obj([ widgetRef ])); }
      }

      // Draw visible text stamp on target page (same as before) and inject AP unless viewer appearance is requested
      try {
        let x1, y1, x2, y2;
        try {
          const rectArr = widget.lookup(PDFName.of('Rect'));
          x1 = rectArr.get(0).asNumber();
          y1 = rectArr.get(1).asNumber();
          x2 = rectArr.get(2).asNumber();
          y2 = rectArr.get(3).asNumber();
        } catch { [x1, y1, x2, y2] = Array.isArray(widgetRectUsed) ? widgetRectUsed : SIGN_RECT; }
        const helv = await pdfDoc2.embedFont(StandardFonts.Helvetica);
        const pad = (n)=>String(n).padStart(2,'0'); const dt = signingTime || new Date();
        const tsText = `${dt.getFullYear()}-${pad(dt.getMonth()+1)}-${pad(dt.getDate())} ${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`;
        const line1 = `Digitally signed by ${userName}`; const line2 = `Date: ${tsText}`; const fontSize=10, lh=14; const padX=6, padY=6;
        const fitText=(t,maxW)=>{ let s=String(t); while(helv.widthOfTextAtSize(s,fontSize)>maxW&&s.length>1) s=s.slice(0,-1); return s; };
        // Ensure sane widget rect; if zero/negative, expand to a default box
        const pageSize = targetPage2.getSize();
        if (!Number.isFinite(x1) || !Number.isFinite(y1) || !Number.isFinite(x2) || !Number.isFinite(y2)) {
          x1 = 36; y1 = 36; x2 = 236; y2 = 86;
        }
        if (x2 <= x1 || y2 <= y1) {
          x2 = Math.min(pageSize.width, x1 + 200);
          y2 = Math.min(pageSize.height, y1 + 50);
          try { widget.set(PDFName.of('Rect'), context.obj([x1, y1, x2, y2])); } catch {}
        }
        // Compute minimal content box and shrink widget to fit, honoring anchor
        const maxTextW = Math.max(0, (x2-x1) - padX*2);
        const line1Fit = fitText(line1, maxTextW);
        const line2Fit = fitText(line2, maxTextW);
        const contentW = Math.max(helv.widthOfTextAtSize(line1Fit, fontSize), helv.widthOfTextAtSize(line2Fit, fontSize));
        const wFit = Math.min(Math.max(0, x2 - x1), Math.ceil(contentW) + padX*2);
        const hFit = Math.min(Math.max(0, y2 - y1), (2*fontSize) + (lh - fontSize) + padY*2);

        let newX1 = x1, newY1 = y1, newX2 = x2, newY2 = y2;
        switch (anchor) {
          case 'top-right':
            newX2 = x2; newX1 = newX2 - wFit; newY2 = y2; newY1 = newY2 - hFit; break;
          case 'bottom-left':
            newX1 = x1; newX2 = newX1 + wFit; newY1 = y1; newY2 = newY1 + hFit; break;
          case 'bottom-right':
            newX2 = x2; newX1 = newX2 - wFit; newY1 = y1; newY2 = newY1 + hFit; break;
          case 'top-left':
          default:
            newX1 = x1; newX2 = newX1 + wFit; newY2 = y2; newY1 = newY2 - hFit; break;
        }
        try { widget.set(PDFName.of('Rect'), context.obj([newX1, newY1, newX2, newY2])); } catch {}

        // Inject a visible appearance stream with text only (transparent background) when not using viewer appearance
        if (!useViewerAppearance) {
          try {
            const esc=(s)=>String(s).replace(/\\/g,'\\\\').replace(/\(/g,'\\(').replace(/\)/g,'\\)');
            const apContent = [
              'BT',
              `/F1 ${fontSize} Tf`,
              `1 0 0 1 ${padX} ${Math.max(0, hFit - padY - fontSize)} Tm`,
              `(${esc(line1Fit)}) Tj`,
              `1 0 0 1 ${padX} ${Math.max(0, hFit - padY - fontSize - lh)} Tm`,
              `(${esc(line2Fit)}) Tj`,
              'ET',
            ].join('\n');
            const apStream = context.stream(apContent, { Type:'XObject', Subtype:'Form', BBox:[0,0, Math.max(1,wFit), Math.max(1,hFit)], Matrix:[1,0,0,1,0,0], Resources:{ Font:{ F1: helv.ref } } });
            widget.set(PDFName.of('AP'), context.obj({ N: context.register(apStream) }));
          } catch {}
        }
        // Draw a subtle white background and text into the new rect on the page for first-open visibility
        try { targetPage2.drawRectangle({ x: newX1, y: newY1, width: Math.max(1, wFit), height: Math.max(1, hFit), color: rgb(1,1,1), opacity: 0.85, borderOpacity: 0 }); } catch {}
        targetPage2.drawText(line1Fit, { x: newX1 + padX, y: newY1 + Math.max(0, hFit - padY - fontSize), size: fontSize, font: helv, color: rgb(0,0,0) });
        if (line2Fit) targetPage2.drawText(line2Fit, { x: newX1 + padX, y: newY1 + Math.max(0, hFit - padY - fontSize - lh), size: fontSize, font: helv, color: rgb(0,0,0) });
        if (debugRect) {
          const borderW = Math.max(0.5, Math.min(2, Math.min((newX2-newX1)/60, (newY2-newY1)/40)));
          targetPage2.drawRectangle({ x: newX1, y: newY1, width: Math.max(1, newX2-newX1), height: Math.max(1, newY2-newY1), borderColor: rgb(1,0,0), borderWidth: borderW, color: undefined });
        }
      } catch {}

      pdfWithPlaceholder = await pdfDoc2.save({ useObjectStreams: false });
    } catch {}

    const signer = new TokenSigner({ dll, pin, signerCert, intermediates, includeESS, signingTime });
    const signedPdf = await new SignPdf().sign(pdfWithPlaceholder, signer);
    // Important: do not modify bytes post-sign; any change invalidates the signature
    return res.json({ ok:true, signedPdfBase64: signedPdf.toString('base64') });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok:false, message: e.message || String(e) });
  }
  });

app.post('/sign/pdf-batch', requireAuth, async (req, res) => {
  try {
    const { dll } = ensureDllPicked();
    const arr = req.body && Array.isArray(req.body.pdfs) ? req.body.pdfs : null;
    if (!arr || !arr.length) return res.status(400).json({ ok:false, message: 'pdfs[] missing' });

    let pin = (req.body && req.body.pin) || DSC_PIN_ENV || '';
    if (!pin && SESSION_PIN) pin = SESSION_PIN;
    let requirePin = (req.body && req.body.requirePin === true) || REQUIRE_PIN_PER_SIGN;
    if (SESSION_PIN && !(req.body && req.body.requirePin === true)) {
      requirePin = false;
    }
    if (requirePin) {
      try {
        pin = await promptPinInteractive('Enter token PIN to sign batch');
        if (req.body && req.body.rememberSessionPin === true && pin) {
          SESSION_PIN = String(pin);
        }
      } catch (e) {
        return res.status(400).json({ ok: false, message: e.message || 'PIN required' });
      }
    }
    if (req.body && req.body.rememberSessionPin === false) {
      SESSION_PIN = '';
    }

    const reason = (req.body && req.body.reason) || 'Signed via DSC Agent';
    const includeESS = req.body && req.body.includeESS !== undefined ? !!req.body.includeESS : true;
    const embedIntermediates = req.body && req.body.embedIntermediates !== undefined ? !!req.body.embedIntermediates : false;
    const signingTime = parseLocalTime(req.body && req.body.signingTime);
    let rectOverride = null;
    if (req.body && Array.isArray(req.body.rect)) {
      rectOverride = req.body.rect.map((n) => Number(n));
    }
    const anchor = (req.body && typeof req.body.anchor === 'string') ? String(req.body.anchor).toLowerCase() : 'top-left';
    const pageReq = req.body && req.body.page;
    const requestedPageIndex = (pageReq === undefined || pageReq === null || pageReq === 'last')
      ? 'last'
      : (typeof pageReq === 'number' ? pageReq : null);
    let rectMode = (req.body && typeof req.body.rectMode === 'string') ? String(req.body.rectMode).toLowerCase() : 'pdf';

    if (!rectOverride) {
      const leftFallback = req.body ? (req.body.left ?? req.body.x) : undefined;
      const topFallback = req.body ? (req.body.top ?? req.body.y) : undefined;
      if (leftFallback !== undefined && topFallback !== undefined) {
        const leftNum = Number(leftFallback);
        const topNum = Number(topFallback);
        if (Number.isFinite(leftNum) && Number.isFinite(topNum)) {
          rectOverride = [leftNum, topNum];
          rectMode = 'top-left';
        }
      }
    }
    // Detect signer and intermediates once for the batch
    const { idHex, certDER } = detectSigningKey(dll, pin);
    const asn = asn1js.fromBER(ab(certDER));
    const signerCert = new pkijs.Certificate({ schema: asn.result });
    const intermediates = await fetchIntermediatesIfRequested(signerCert, embedIntermediates);
    const userName = signerCert.subject.typesAndValues.find(tv => tv.type === '2.5.4.3')?.value.valueBlock.value || 'Unknown';

    const signer = new TokenSigner({ dll, pin, signerCert, intermediates, includeESS, signingTime });

    async function signOne(b64) {
      try {
        const inputBuf = Buffer.from(b64, 'base64');
        assertNoExistingSignature(inputBuf);

        let pdfForPlaceholder = inputBuf;
        try {
          const pdfDoc = await PDFDocument.load(inputBuf);
          pdfDoc.catalog.set(PDFName.of('NeedAppearances'), pdfDoc.context.obj(true));
          pdfForPlaceholder = await pdfDoc.save({ useObjectStreams: false });
        } catch {}

        // Compute final widget rect (respect top-left mode with [left, top])
        let widgetRect = rectOverride || SIGN_RECT;
        let pdfWithPlaceholder;
        try {
          const pdfDoc2 = await PDFDocument.load(pdfForPlaceholder);
          // If rectMode is top-left with [left, top], convert using last page size
          try {
            const pageCountTL = pdfDoc2.getPageCount();
            const targetIndexTL = (requestedPageIndex === 'last') ? (pageCountTL - 1)
              : (requestedPageIndex && requestedPageIndex > 0 ? Math.min(pageCountTL - 1, requestedPageIndex - 1) : 0);
            const szTL = pdfDoc2.getPages()[targetIndexTL].getSize();
            if (rectOverride && rectOverride.length === 2 && rectMode === 'top-left') {
              const L = Number(rectOverride[0]) || 0;
              const T = Number(rectOverride[1]) || 0;
              const defaultW = Math.max(1, SIGN_RECT[2] - SIGN_RECT[0]);
              const defaultH = Math.max(1, SIGN_RECT[3] - SIGN_RECT[1]);
              const defW = Math.max(1, Math.min(defaultW, Math.floor(szTL.width - Math.max(0, L))));
              const defH = Math.max(1, Math.min(defaultH,  Math.floor(szTL.height - Math.max(0, T))));
              const x1 = Math.max(0, L);
              const y2 = Math.max(0, szTL.height - T);
              const x2 = Math.min(szTL.width,  x1 + defW);
              const y1 = Math.max(0, y2 - defH);
              widgetRect = [x1, y1, x2, y2];
              rectOverride = widgetRect;
              rectMode = 'pdf';
            } else if (rectOverride && rectOverride.length === 4 && rectMode !== 'top-left') {
              const [rx1, ry1, rx2, ry2] = rectOverride;
              widgetRect = [Math.min(rx1, rx2), Math.min(ry1, ry2), Math.max(rx1, rx2), Math.max(ry1, ry2)];
            }
          } catch {}

          pdflibAddPlaceholder({ pdfDoc: pdfDoc2, reason: String(reason||''), contactInfo: '', location: '', name: String(userName||''), signingTime, signatureLength: 32768, widgetRect });
          try {
            const context = pdfDoc2.context;
            const acroForm = pdfDoc2.catalog.lookup(PDFName.of('AcroForm'));
            const fields = acroForm.lookup(PDFName.of('Fields'));
            const lastFieldRef = fields.get(fields.size() - 1);
            const widget = context.lookup(lastFieldRef);
            const rectArr = widget.lookup(PDFName.of('Rect'));
            let x1 = rectArr.get(0).asNumber();
            let y1 = rectArr.get(1).asNumber();
            let x2 = rectArr.get(2).asNumber();
            let y2 = rectArr.get(3).asNumber();
            if (rectOverride) {
              const [rx1, ry1, rx2, ry2] = rectOverride;
              x1 = Math.min(rx1, rx2); x2 = Math.max(rx1, rx2);
              y1 = Math.min(ry1, ry2); y2 = Math.max(ry1, ry2);
              widget.set(PDFName.of('Rect'), context.obj([x1, y1, x2, y2]));
            }
            const wMax = Math.max(0, x2 - x1);
            const hMax = Math.max(0, y2 - y1);

            const helv = await pdfDoc2.embedFont(StandardFonts.Helvetica);
            const pad = (n) => String(n).padStart(2, '0');
            const dt = signingTime || new Date();
            const tsText = `${dt.getFullYear()}-${pad(dt.getMonth()+1)}-${pad(dt.getDate())} ${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`;
            const line1 = `Digitally signed by ${userName}`;
            const line2 = `Date: ${tsText}`;
            const fontSize = 10;
            const lh = 14;
            const padX = 6, padY = 6;
            const fitText = (t, maxW) => {
              let s = String(t);
              while (helv.widthOfTextAtSize(s, fontSize) > maxW && s.length > 1) s = s.slice(0, -1);
              if (helv.widthOfTextAtSize(s, fontSize) > maxW && s.length > 1) s = s.slice(0, -1);
              if (s.length < String(t).length) s = s.slice(0, -1) + '�';
              return s;
            };
            const maxTextW = Math.max(0, wMax - padX*2);
            const line1Fit = fitText(line1, maxTextW);
            const line2Fit = fitText(line2, maxTextW);
            const contentW = Math.max(helv.widthOfTextAtSize(line1Fit, fontSize), helv.widthOfTextAtSize(line2Fit, fontSize));
            const w = Math.min(wMax, Math.ceil(contentW) + padX*2);
            const h = Math.min(hMax, (2*fontSize) + (lh - fontSize) + padY*2);
            let newX1 = x1, newY1 = y1, newX2 = x2, newY2 = y2;
            switch (anchor) {
              case 'top-right':
                newX2 = x2; newX1 = newX2 - w; newY2 = y2; newY1 = newY2 - h; break;
              case 'bottom-left':
                newX1 = x1; newX2 = newX1 + w; newY1 = y1; newY2 = newY1 + h; break;
              case 'bottom-right':
                newX2 = x2; newX1 = newX2 - w; newY1 = y1; newY2 = newY1 + h; break;
              case 'top-left':
              default:
                newX1 = x1; newX2 = newX1 + w; newY2 = y2; newY1 = newY2 - h; break;
            }
            widget.set(PDFName.of('Rect'), context.obj([newX1, newY1, newX2, newY2]));
            const esc = (s) => String(s).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
            const content = [
              'BT',
              `/F1 ${fontSize} Tf`,
              `1 0 0 1 ${padX} ${Math.max(0, h - padY - fontSize)} Tm`,
              `(${esc(line1Fit)}) Tj`,
              `1 0 0 1 ${padX} ${Math.max(0, h - padY - fontSize - lh)} Tm`,
              `(${esc(line2Fit)}) Tj`,
              'ET',
            ].join('\n');
            const apStream = context.stream(content, { Type: 'XObject', Subtype: 'Form', BBox: [0, 0, w, h], Matrix: [1,0,0,1,0,0], Resources: { Font: { F1: helv.ref } } });
            widget.set(PDFName.of('AP'), context.obj({ N: context.register(apStream) }));

            try {
              const pageCount = pdfDoc2.getPageCount();
              if (requestedPageIndex !== null && requestedPageIndex !== undefined && pageCount > 1) {
                const targetIndex = (requestedPageIndex === 'last') ? (pageCount - 1) : (Math.max(0, Math.min(pageCount - 1, (requestedPageIndex > 0 ? requestedPageIndex - 1 : 0))));
                const targetPage = pdfDoc2.getPages()[targetIndex];
                widget.set(PDFName.of('P'), targetPage.ref);
                for (let i = 0; i < pageCount; i++) {
                  const pg = pdfDoc2.getPages()[i];
                  try {
                    const annots = pg.node.lookup(PDFName.of('Annots'));
                    const size = annots.size ? annots.size() : (annots.array ? annots.array.length : 0);
                    for (let j = size - 1; j >= 0; j--) {
                      const ref = annots.get ? annots.get(j) : (annots.array ? annots.array[j] : null);
                      if (ref && ref === lastFieldRef && annots.remove) annots.remove(j);
                    }
                  } catch {}
                }
                try {
                  let annots = targetPage.node.lookupMaybe ? targetPage.node.lookupMaybe(PDFName.of('Annots')) : null;
                  if (!annots) targetPage.node.set(PDFName.of('Annots'), context.obj([lastFieldRef]));
                  else if (annots.push) annots.push(lastFieldRef);
                } catch {}
              }
            } catch {}
          } catch {}
          pdfWithPlaceholder = await pdfDoc2.save({ useObjectStreams: false });
        } catch (eLib) {
          pdfWithPlaceholder = plainAddPlaceholder({ pdfBuffer: Buffer.from(pdfForPlaceholder), reason, name: userName, signatureLength: 32768, widgetRect });
        }

        const signedPdf = await new SignPdf().sign(pdfWithPlaceholder, signer);
        return { ok: true, signedPdfBase64: signedPdf.toString('base64') };
      } catch (e) {
        return { ok: false, message: e.message || String(e) };
      }
    }

    const results = [];
    for (const b64 of arr) {
      // Serialize operations to keep token interactions simple and predictable
      // (Smartcards often dislike concurrent sessions across rapid calls.)
      // If we need concurrency later, we can gate via a queue.
      /* eslint-disable no-await-in-loop */
      results.push(await signOne(b64));
      /* eslint-enable no-await-in-loop */
    }
    return res.json({ ok: true, results });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok:false, message: e.message });
  }
});
// Optional local-only shutdown endpoint for dev convenience
app.post('/shutdown', (req, res) => {
  // Only allow when explicitly enabled and from localhost
  const remote = (req.socket && req.socket.remoteAddress) || '';
  const isLocal = remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
  if (!ALLOW_LOCAL_SHUTDOWN || !isLocal) return res.status(403).json({ ok: false, message: 'Forbidden' });
  res.json({ ok: true });
  // Defer shutdown until after response flush
  setTimeout(() => shutdown(0), 50);
});

const server = app.listen(PORT, '127.0.0.1', () => {
  console.log(`[dsc-agent] v${VERSION} listening on http://127.0.0.1:${PORT}`);
});

function shutdown(code = 0) {
  try {
    console.log('[dsc-agent] Shutting down...');
    server.close(() => {
      process.exit(code);
    });
    // Fallback exit in case of hung connections
    setTimeout(() => process.exit(code), 2000).unref();
  } catch (e) {
    process.exit(code);
  }
}

// Handle termination signals so IDE Stop/CTRL+C work reliably
process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));




