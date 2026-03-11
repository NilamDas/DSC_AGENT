// =============================================
// File: dsc-agent.js  (local client service)
// =============================================
// A tiny localhost HTTP service that any web app can call via JavaScript
// to sign PDFs with a USB DSC token (PKCS#11). Minimal config: it auto-detects
// the signing key (even when the token exposes separate encryption/signing keys).



// Endpoints
//  GET  /health                 → { ok: true, version, dll, slotPresent }
//  POST /sign/pdf               ← { pdfBase64, reason?, profile?, embedIntermediates?, includeESS?, signingTime? (YYYY-MM-DD HH:mm:ss), pin? }
//                                → { ok: true, signedPdfBase64 }
//  GET  /certs                  → { ok: true, pairs:[{ckaIdHex, subjectCN, label}] }
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
function pdfRefEquals(a, b) {
  try {
    if (!a || !b) return false;
    if (a === b) return true;
    const toRefId = (ref) => {
      const r = (ref && ref.ref) ? ref.ref : ref;
      if (!r) return null;
      const objNum = (typeof r.objectNumber === 'number') ? r.objectNumber : null;
      const genNum = (typeof r.generationNumber === 'number') ? r.generationNumber : 0;
      if (objNum === null) return null;
      return `${objNum}:${genNum}`;
    };
    const idA = toRefId(a);
    const idB = toRefId(b);
    if (idA && idB) return idA === idB;
  } catch {}
  return false;
}

function pdfArrayToRefs(arr) {
  const out = [];
  if (!arr) return out;
  try {
    const size = arr.size ? arr.size() : (arr.array ? arr.array.length : 0);
    for (let i = 0; i < size; i++) {
      let ref = null;
      try { ref = arr.get ? arr.get(i) : null; } catch {}
      if (!ref && arr.array && i < arr.array.length) ref = arr.array[i];
      if (ref) out.push(ref);
    }
  } catch {}
  return out;
}

async function configureSignatureWidget(pdfDoc, options = {}) {
  const {
    userName = 'Unknown',
    signingTime = null,
    rectOverride = null,
    rectMode = 'pdf',
    anchor = 'top-left',
    requestedPageIndex = 'last',
    widgetRect = SIGN_RECT,
  } = options || {};
  try {
    const context = pdfDoc.context;
    const acroForm = pdfDoc.catalog.lookup(PDFName.of('AcroForm'));
    if (!acroForm) return;
    let fields = acroForm.lookup(PDFName.of('Fields'));
    const fieldRefs = pdfArrayToRefs(fields);
    if (!fieldRefs.length) return;
    const fieldsIndex = fieldRefs.length > 0 ? fieldRefs.length - 1 : 0;
    let fieldRef = fieldRefs[fieldsIndex] || null;
    let field = fieldRef ? context.lookup(fieldRef) : null;
    let widgetRef = null;
    let widget = null;
    let kidsArray = null;
    try { kidsArray = field && field.lookupMaybe ? field.lookupMaybe(PDFName.of('Kids')) : null; } catch {}
    const kidRefs = pdfArrayToRefs(kidsArray);
    if (kidRefs.length > 0) {
      widgetRef = kidRefs[0];
      try { widget = context.lookup(widgetRef); } catch {}
    } else if (fieldRef) {
      widgetRef = fieldRef;
      try { widget = context.lookup(widgetRef); } catch {}
      try {
        const kidsArr = context.obj([ widgetRef ]);
        const fieldDict = context.obj({ FT: PDFName.of('Sig'), Kids: kidsArr, T: PDFString.of('Signature1') });
        try {
          const vMaybe = widget && widget.lookupMaybe ? widget.lookupMaybe(PDFName.of('V')) : null;
          if (vMaybe) fieldDict.set(PDFName.of('V'), vMaybe);
        } catch {}
        fieldRef = context.register(fieldDict);
        try { field = context.lookup(fieldRef); } catch {}
        try { kidsArray = field.lookupMaybe ? field.lookupMaybe(PDFName.of('Kids')) : null; } catch {}
        try { if (widget) widget.set(PDFName.of('Parent'), fieldRef); } catch {}
        fieldRefs[fieldsIndex] = fieldRef;
      } catch {}
    }
    if (!widget && widgetRef) { try { widget = context.lookup(widgetRef); } catch {} }
    if (!widget && fieldRef) { widgetRef = fieldRef; try { widget = context.lookup(fieldRef); } catch {} }
    if (!widget || !fieldRef) return;

    try { field.set(PDFName.of('FT'), PDFName.of('Sig')); } catch {}
    try {
      const parentMaybe = widget && widget.lookupMaybe ? widget.lookupMaybe(PDFName.of('Parent')) : null;
      if (!parentMaybe && widgetRef && fieldRef && !pdfRefEquals(widgetRef, fieldRef)) widget.set(PDFName.of('Parent'), fieldRef);
    } catch {}

    try { field.set(PDFName.of('T'), PDFString.of('Signature1')); } catch {}

    const cleanRefs = [];
    let hasField = false;
    for (const ref of fieldRefs) {
      if (!ref) continue;
      if (widgetRef && pdfRefEquals(ref, widgetRef)) continue;
      if (fieldRef && pdfRefEquals(ref, fieldRef)) {
        if (!hasField) {
          cleanRefs.push(fieldRef);
          hasField = true;
        }
        continue;
      }
      cleanRefs.push(ref);
    }
    if (fieldRef && !hasField) cleanRefs.push(fieldRef);
    fields = context.obj(cleanRefs);
    try { acroForm.set(PDFName.of('Fields'), fields); } catch {}

    const widgetRefsToRemove = kidRefs.filter((ref) => !!ref);
    if (widgetRef && !widgetRefsToRemove.some((ref) => pdfRefEquals(ref, widgetRef))) widgetRefsToRemove.push(widgetRef);

    try {
      if (widgetRef) field.set(PDFName.of('Kids'), context.obj([ widgetRef ]));
      else if (field.delete) field.delete(PDFName.of('Kids'));
    } catch {}

    const pageCount = pdfDoc.getPageCount();
    const tIndex = (requestedPageIndex === 'last') ? (pageCount - 1) : (requestedPageIndex && requestedPageIndex > 0 ? Math.min(pageCount - 1, requestedPageIndex - 1) : 0);
    const targetPage = pdfDoc.getPages()[Math.max(0, Math.min(pageCount - 1, tIndex))];

    let x1, y1, x2, y2;
    try { const rectArr = widget.lookup(PDFName.of('Rect')); x1 = rectArr.get(0).asNumber(); y1 = rectArr.get(1).asNumber(); x2 = rectArr.get(2).asNumber(); y2 = rectArr.get(3).asNumber(); }
    catch { [x1, y1, x2, y2] = Array.isArray(widgetRect) ? widgetRect : SIGN_RECT; }
    if (rectOverride) {
      if ((rectMode || 'pdf') === 'top-left') {
        const arr = rectOverride.map((n) => parseInt(n, 10));
        const left = Number.isFinite(arr[0]) ? arr[0] : 0;
        const top = Number.isFinite(arr[1]) ? arr[1] : 0;
        const sz = targetPage.getSize();
        const defW = Math.max(1, Math.min(200, Math.floor(sz.width - Math.max(0, left))));
        const defH = Math.max(1, Math.min(50, Math.floor(sz.height - Math.max(0, top))));
        const Wd = (arr.length >= 3 && Number.isFinite(arr[2])) ? Math.max(1, arr[2]) : defW;
        const Ht = (arr.length >= 4 && Number.isFinite(arr[3])) ? Math.max(1, arr[3]) : defH;
        x1 = Math.max(0, left);
        const y2tl = Math.max(0, sz.height - top);
        x2 = Math.min(sz.width, x1 + Wd);
        y1 = Math.max(0, y2tl - Ht);
        y2 = y2tl;
      } else {
        const [rx1, ry1, rx2, ry2] = rectOverride;
        x1 = Math.min(rx1, rx2); x2 = Math.max(rx1, rx2);
        y1 = Math.min(ry1, ry2); y2 = Math.max(ry1, ry2);
      }
    }

    const szp = targetPage.getSize();
    if (!Number.isFinite(x1) || !Number.isFinite(y1) || !Number.isFinite(x2) || !Number.isFinite(y2)) { x1=36; y1=36; x2=236; y2=86; }
    if (x2 <= x1 || y2 <= y1) { x2 = Math.min(szp.width, x1+200); y2 = Math.min(szp.height, y1+50); }

    try { widget.set(PDFName.of('Rect'), context.obj([x1, y1, x2, y2])); } catch {}
    try { widget.set(PDFName.of('P'), targetPage.ref); } catch {}

    const helv = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const pad = (n) => String(n).padStart(2, '0');
    const dt = signingTime || new Date();
    const tsText = `${dt.getFullYear()}-${pad(dt.getMonth()+1)}-${pad(dt.getDate())} ${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`;
    const line1 = `Digitally signed by ${userName}`;
    const line2 = `Date: ${tsText}`;
    const fontSize = 10; const lh = 14; const padX=6, padY=6;
    const fitText = (t, maxW) => { let s = String(t); while (helv.widthOfTextAtSize(s, fontSize) > maxW && s.length > 1) s = s.slice(0, -1); return s; };
    const maxTextW = Math.max(0, (x2-x1) - padX*2);
    const line1Fit = fitText(line1, maxTextW);
    const line2Fit = fitText(line2, maxTextW);
    const contentW = Math.max(helv.widthOfTextAtSize(line1Fit, fontSize), helv.widthOfTextAtSize(line2Fit, fontSize));
    const w = Math.min(Math.max(0, x2-x1), Math.ceil(contentW) + padX*2);
    const h = Math.min(Math.max(0, y2-y1), (2*fontSize) + (lh - fontSize) + padY*2);
    let newX1=x1, newY1=y1, newX2=x2, newY2=y2;
    switch (anchor) {
      case 'top-right': newX2=x2; newX1=newX2-w; newY2=y2; newY1=newY2-h; break;
      case 'bottom-left': newX1=x1; newX2=newX1+w; newY1=y1; newY2=newY1+h; break;
      case 'bottom-right': newX2=x2; newX1=newX2-w; newY1=y1; newY2=newY1+h; break;
      case 'top-left': default: newX1=x1; newX2=newX1+w; newY2=y2; newY1=newY2-h; break;
    }
    try { widget.set(PDFName.of('Rect'), context.obj([newX1,newY1,newX2,newY2])); } catch {}

    const esc = (s) => String(s).replace(new RegExp('\\', 'g'), '\\').replace(/\(/g, '\(').replace(/\)/g, '\)');
    const content = ['BT', `/F1 ${fontSize} Tf`, `1 0 0 1 ${padX} ${Math.max(0, h - padY - fontSize)} Tm`, `(${esc(line1Fit)}) Tj`, `1 0 0 1 ${padX} ${Math.max(0, h - padY - fontSize - lh)} Tm`, `(${esc(line2Fit)}) Tj`, 'ET'].join('\n');
    const apStream = context.stream(content, { Type:'XObject', Subtype:'Form', BBox:[0,0, Math.max(1,w), Math.max(1,h)], Matrix:[1,0,0,1,0,0], Resources:{ Font:{ F1: helv.ref } } });
    try { widget.set(PDFName.of('AP'), context.obj({ N: context.register(apStream) })); } catch {}
    try { const acro = pdfDoc.catalog.lookup(PDFName.of('AcroForm')); acro.set(PDFName.of('SigFlags'), PDFNumber.of(3)); if (pdfDoc.catalog.delete) pdfDoc.catalog.delete(PDFName.of('NeedAppearances')); } catch {}

    const pages = pdfDoc.getPages();
    for (let i = 0; i < pages.length; i++) {
      const pg = pages[i];
      try {
        let ann = pg.node.lookupMaybe ? pg.node.lookupMaybe(PDFName.of('Annots')) : null;
        let arr = [];
        if (ann) {
          if (ann.size && ann.get) { for (let j = 0; j < ann.size(); j++) arr.push(ann.get(j)); }
          else if (ann.array) { for (const r of ann.array) arr.push(r); }
        }
        const filtered = [];
        for (const r of arr) {
          if (pdfRefEquals(r, fieldRef)) continue;
          if (widgetRefsToRemove.some((ref) => pdfRefEquals(r, ref))) continue;
          filtered.push(r);
        }
        if (i === tIndex && widgetRef) filtered.push(widgetRef);
        if (filtered.length) pg.node.set(PDFName.of('Annots'), pdfDoc.context.obj(filtered));
        else { try { pg.node.delete && pg.node.delete(PDFName.of('Annots')); } catch {} }
      } catch {}
    }
    try {
      let annT = targetPage.node.lookupMaybe ? targetPage.node.lookupMaybe(PDFName.of('Annots')) : null;
      let items = [];
      if (annT) {
        if (annT.size && annT.get) { for (let j = 0; j < annT.size(); j++) items.push(annT.get(j)); }
        else if (annT.array) { for (const r of annT.array) items.push(r); }
      }
      let presentT = false;
      for (const r of items) { if (pdfRefEquals(r, widgetRef)) { presentT = true; break; } }
      if (!presentT && widgetRef) {
        items.push(widgetRef);
        targetPage.node.set(PDFName.of('Annots'), pdfDoc.context.obj(items));
      }
    } catch {}

    try {
      const yTopDraw = Math.max(0, newY1 + (newY2-newY1) - padY - fontSize);
      targetPage.drawRectangle({ x:newX1, y:newY1, width: Math.max(1,w), height: Math.max(1,h), color: rgb(1,1,1), opacity: 1, borderOpacity: 0 });
      targetPage.drawText(line1Fit, { x:newX1+padX, y:yTopDraw, size:fontSize, font:helv, color: rgb(0,0,0) });
      targetPage.drawText(line2Fit, { x:newX1+padX, y: Math.max(0, yTopDraw - lh), size:fontSize, font:helv, color: rgb(0,0,0) });
    } catch {}
  } catch {}
}

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
      if (res.statusCode !== 200) return reject(new Error(`GET ${url} → HTTP ${res.statusCode}`));
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

// Add this new function
async function calculateDynamicRect(pdfDoc, page, text, position) {
  const font = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const fontSize = 9;
  const padding = 4;
  
  // Calculate text dimensions
  const textWidth = font.widthOfTextAtSize(text, fontSize);
  const textHeight = font.heightAtSize(fontSize);
  
  // Add padding for signature visual
  const width = textWidth + (padding * 2);
  const height = textHeight + (padding * 2);
  
  const pageWidth = page.getWidth();
  const pageHeight = page.getHeight();
  
  let x1, y1, x2, y2;
  
  if (Array.isArray(position)) {
    // Fixed position provided
    [x1, y1] = position;
    x2 = x1 + width;
    y2 = y1 + height;
  } else {
    // Default bottom-right position
    x1 = pageWidth - width - padding;
    y1 = padding;
    x2 = pageWidth - padding;
    y2 = height + padding;
  }
  
  return clampRectToPage([x1, y1, x2, y2], { width: pageWidth, height: pageHeight });
}

// Ensure no existing signature fields are present
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
      case 'top-right': newX2=x2; newX1=newX2-w; newY2=y2; newY1=newY2-h; break;
      case 'bottom-left': newX1=x1; newX2=newX1+w; newY1=y1; newY2=newY1+h; break;
      case 'bottom-right': newX2=x2; newX1=newX2-w; newY1=y1; newY2=newY1+h; break;
      case 'top-left': default: newX1=x1; newX2=newX1+w; newY2=y2; newY1=newY2-h; break;
    }
    try { page.drawRectangle({ x: newX1, y: newY1, width: Math.max(1,w), height: Math.max(1,h), color: rgb(1,1,1), opacity: 0.85, borderOpacity: 0 }); } catch {}
    const yTop = Math.max(0, newY1 + h - padY - fontSize);
    try { page.drawText(line1Fit, { x: newX1 + padX, y: yTop, size: fontSize, font: helv, color: rgb(0,0,0) }); } catch {}
    try { page.drawText(line2Fit, { x: newX1 + padX, y: Math.max(0, yTop - lh), size: fontSize, font: helv, color: rgb(0,0,0) }); } catch {}
  }
  return await pdfDoc.save({ useObjectStreams: false });
}

// Build placeholder and inject a visible AP + draw text into page content
// This mirrors the working /sign/pdf stamping path to keep behavior identical across endpoints.
async function buildPlaceholderWithVisibleStamp(pdfInputBytes, userName, reason, signingTime, rectOverride, rectMode, anchor, requestedPageIndex, stampAllPages) {
  let pdfForPlaceholder = pdfInputBytes;
  try {
    const pdfDoc = await PDFDocument.load(pdfInputBytes);
    try { pdfDoc.catalog.set(PDFName.of('NeedAppearances'), pdfDoc.context.obj(true)); } catch {}
    pdfForPlaceholder = await pdfDoc.save({ useObjectStreams: false });
  } catch {}

  // Optional: pre-stamp all pages except target page
  if (stampAllPages) {
    try {
      // Compute stamping rect with top-left support
      let stampRect = rectOverride || SIGN_RECT;
      try {
        const tmp = await PDFDocument.load(pdfForPlaceholder);
        const pageCount = tmp.getPageCount();
        const targetIndex = (requestedPageIndex === 'last') ? (pageCount - 1)
          : (requestedPageIndex && requestedPageIndex > 0 ? Math.min(pageCount - 1, requestedPageIndex - 1) : 0);
        const sz = tmp.getPages()[targetIndex].getSize();
        const mode = rectMode || 'pdf';
        if (rectOverride && mode === 'top-left') {
          const arr = rectOverride.map((n) => parseInt(n, 10));
          const left = Number.isFinite(arr[0]) ? arr[0] : 0;
          const top = Number.isFinite(arr[1]) ? arr[1] : 0;
          const defW = Math.max(1, Math.min(200, Math.floor(sz.width - Math.max(0, left))));
          const defH = Math.max(1, Math.min(50, Math.floor(sz.height - Math.max(0, top))));
          const width = (arr.length >= 3 && Number.isFinite(arr[2])) ? Math.max(1, arr[2]) : defW;
          const height = (arr.length >= 4 && Number.isFinite(arr[3])) ? Math.max(1, arr[3]) : defH;
          const x1 = Math.max(0, left);
          const y2 = Math.max(0, sz.height - top);
          const x2 = Math.min(sz.width, x1 + width);
          const y1 = Math.max(0, y2 - height);
          stampRect = [x1, y1, x2, y2];
        }
      } catch {}
      pdfForPlaceholder = await applyTextStampToAllPages(pdfForPlaceholder, userName, signingTime, stampRect, anchor, requestedPageIndex);
    } catch {}
  }

  const widgetRect = rectOverride || SIGN_RECT;
  const pdfDoc2 = await PDFDocument.load(pdfForPlaceholder);
  pdflibAddPlaceholder({
    pdfDoc: pdfDoc2,
    reason: String(reason || ''),
    contactInfo: '',
    location: '',
    name: String(userName || ''),
    signingTime,
    signatureLength: 32768,
    widgetRect,
  });

  try {
    const context = pdfDoc2.context;
    const acroForm = pdfDoc2.catalog.lookup(PDFName.of('AcroForm'));
    const fields = acroForm.lookup(PDFName.of('Fields'));
    const fieldsCount = (() => { try { return fields.size ? fields.size() : (fields.array ? fields.array.length : 0); } catch { return 0; } })();
    const fieldsIndex = fieldsCount > 0 ? (fieldsCount - 1) : 0;
    let fieldRef = null;
    let field = null;
    try { fieldRef = fields.get ? fields.get(fieldsIndex) : (fields.array ? fields.array[fieldsIndex] : null); } catch {}
    if (fieldRef) { try { field = context.lookup(fieldRef); } catch {} }
    let widgetRef = null;
    let widget = null;
    let kids = null;
    try { kids = field && field.lookupMaybe ? field.lookupMaybe(PDFName.of('Kids')) : null; } catch {}
    let kidsCount = 0;
    if (kids) { try { kidsCount = kids.size ? kids.size() : (kids.array ? kids.array.length : 0); } catch {} }
    if (kids && kidsCount > 0) {
      try { widgetRef = kids.get ? kids.get(0) : (kids.array ? kids.array[0] : null); if (widgetRef) widget = context.lookup(widgetRef); } catch {}
    } else if (fieldRef) {
      widgetRef = fieldRef;
      widget = field;
      try {
        const kidsArr = context.obj([ widgetRef ]);
        const fieldDict = context.obj({ FT: PDFName.of('Sig'), Kids: kidsArr, T: PDFString.of('Signature1') });
        try {
          const vMaybe = widget && widget.lookupMaybe ? widget.lookupMaybe(PDFName.of('V')) : null;
          if (vMaybe) fieldDict.set(PDFName.of('V'), vMaybe);
        } catch {}
        fieldRef = context.register(fieldDict);
        try { field = context.lookup(fieldRef); } catch {}
        try { kids = field.lookupMaybe ? field.lookupMaybe(PDFName.of('Kids')) : null; } catch {}
        try { if (widget) widget.set(PDFName.of('Parent'), fieldRef); } catch {}
        let replaced = false;
        try {
          if (fields && fields.set && fieldsCount > 0) { fields.set(fieldsIndex, fieldRef); replaced = true; }
        } catch {}
        if (!replaced) {
          const arr = [];
          if (fieldsCount === 0) arr.push(fieldRef);
          else {
            for (let i = 0; i < fieldsCount; i++) {
              let ref = null;
              try { ref = fields.get ? fields.get(i) : null; } catch {}
              if (!ref && fields && fields.array && i < fields.array.length) ref = fields.array[i];
              arr.push(i === fieldsIndex ? fieldRef : ref);
            }
          }
          acroForm.set(PDFName.of('Fields'), context.obj(arr));
        }
      } catch {}
    }
    if (!widget && fieldRef) { widgetRef = fieldRef; widget = field; }
    // Determine target page
    const pageCount = pdfDoc2.getPageCount();
    const tIndex = (requestedPageIndex === 'last') ? (pageCount - 1)
      : (requestedPageIndex && requestedPageIndex > 0 ? Math.min(pageCount - 1, requestedPageIndex - 1) : 0);
    const targetPage = pdfDoc2.getPages()[tIndex];
    // Read rect safely
    let x1, y1, x2, y2;
    try { const rectArr = widget.lookup(PDFName.of('Rect')); x1 = rectArr.get(0).asNumber(); y1 = rectArr.get(1).asNumber(); x2 = rectArr.get(2).asNumber(); y2 = rectArr.get(3).asNumber(); }
    catch { [x1, y1, x2, y2] = widgetRect; }
    // Ensure field type and parent/kids linkage
    try { field.set(PDFName.of('FT'), PDFName.of('Sig')); } catch {}
    try {
      const parentMaybe = widget && widget.lookupMaybe ? widget.lookupMaybe(PDFName.of('Parent')) : null;
      if (!parentMaybe && widgetRef && fieldRef && widgetRef !== fieldRef) widget.set(PDFName.of('Parent'), fieldRef);
    } catch {}
    try {
      let kids = field.lookupMaybe ? field.lookupMaybe(PDFName.of('Kids')) : null;
      if (!kids) field.set(PDFName.of('Kids'), context.obj([ widgetRef ]));
      else if (kids.push) {
        let has = false; try { const size = kids.size ? kids.size() : (kids.array ? kids.array.length : 0); for (let i=0;i<size;i++){ const r = kids.get ? kids.get(i) : kids.array[i]; if (r === widgetRef) { has = true; break; } } } catch {}
        if (!has) kids.push(widgetRef);
      }
    } catch {}

    // Apply rect override
    if (rectOverride) {
      if ((rectMode || 'pdf') === 'top-left') {
        const arr = rectOverride.map((n) => parseInt(n, 10));
        const left = Number.isFinite(arr[0]) ? arr[0] : 0;
        const top = Number.isFinite(arr[1]) ? arr[1] : 0;
        const sz = targetPage.getSize();
        const defW = Math.max(1, Math.min(200, Math.floor(sz.width - Math.max(0, left))));
        const defH = Math.max(1, Math.min(50, Math.floor(sz.height - Math.max(0, top))));
        const Wd = (arr.length >= 3 && Number.isFinite(arr[2])) ? Math.max(1, arr[2]) : defW;
        const Ht = (arr.length >= 4 && Number.isFinite(arr[3])) ? Math.max(1, arr[3]) : defH;
        x1 = Math.max(0, left);
        const y2tl = Math.max(0, sz.height - top);
        x2 = Math.min(sz.width, x1 + Wd);
        y1 = Math.max(0, y2tl - Ht);
        y2 = y2tl;
      } else {
        const [rx1, ry1, rx2, ry2] = rectOverride;
        x1 = Math.min(rx1, rx2); x2 = Math.max(rx1, rx2);
        y1 = Math.min(ry1, ry2); y2 = Math.max(ry1, ry2);
      }
      try { widget.set(PDFName.of('Rect'), context.obj([x1, y1, x2, y2])); } catch {}
    }
    // Ensure sane rect
    const szp = targetPage.getSize();
    if (!Number.isFinite(x1) || !Number.isFinite(y1) || !Number.isFinite(x2) || !Number.isFinite(y2)) { x1=36; y1=36; x2=236; y2=86; try { widget.set(PDFName.of('Rect'), context.obj([x1, y1, x2, y2])); } catch {} }
    if (x2 <= x1 || y2 <= y1) { x2 = Math.min(szp.width, x1+200); y2 = Math.min(szp.height, y1+50); try { widget.set(PDFName.of('Rect'), context.obj([x1, y1, x2, y2])); } catch {} }

    // Build AP + draw text
    const helv = await pdfDoc2.embedFont(StandardFonts.Helvetica);
    const pad = (n) => String(n).padStart(2, '0');
    const dt = signingTime || new Date();
    const tsText = `${dt.getFullYear()}-${pad(dt.getMonth()+1)}-${pad(dt.getDate())} ${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`;
    const line1 = `Digitally signed by ${userName}`;
    const line2 = `Date: ${tsText}`;
    const fontSize = 10; const lh = 14; const padX=6, padY=6;
    const fitText = (t, maxW) => { let s = String(t); while (helv.widthOfTextAtSize(s, fontSize) > maxW && s.length > 1) s = s.slice(0, -1); return s; };
    const maxTextW = Math.max(0, (x2-x1) - padX*2);
    const line1Fit = fitText(line1, maxTextW);
    const line2Fit = fitText(line2, maxTextW);
    const contentW = Math.max(helv.widthOfTextAtSize(line1Fit, fontSize), helv.widthOfTextAtSize(line2Fit, fontSize));
    const w = Math.min(Math.max(0, x2-x1), Math.ceil(contentW) + padX*2);
    const h = Math.min(Math.max(0, y2-y1), (2*fontSize) + (lh - fontSize) + padY*2);
    // Shrink and align within rect per anchor
    let newX1=x1, newY1=y1, newX2=x2, newY2=y2;
    switch (anchor) { case 'top-right': newX2=x2; newX1=newX2-w; newY2=y2; newY1=newY2-h; break; case 'bottom-left': newX1=x1; newX2=newX1+w; newY1=y1; newY2=newY1+h; break; case 'bottom-right': newX2=x2; newX1=newX2-w; newY1=y1; newY2=newY1+h; break; case 'top-left': default: newX1=x1; newX2=newX1+w; newY2=y2; newY1=newY2-h; break; }
    try { widget.set(PDFName.of('Rect'), context.obj([newX1,newY1,newX2,newY2])); } catch {}

    // Ensure we have a real widget annotation ref (not the field ref)
    try {
      let isRealWidget = false;
      try {
        const subtype = widget.lookupMaybe ? widget.lookupMaybe(PDFName.of('Subtype')) : null;
        if (subtype && subtype.name && typeof subtype.name === 'string') {
          isRealWidget = (subtype.name === 'Widget');
        }
      } catch {}
      if (!isRealWidget || widgetRef === fieldRef) {
        const newAnnot = context.obj({ Type: 'Annot', Subtype: 'Widget', Rect:[newX1,newY1,newX2,newY2], P: targetPage.ref, F:4, Parent: fieldRef });
        const newAnnotRef = context.register(newAnnot);
        try {
          let kids = field.lookupMaybe ? field.lookupMaybe(PDFName.of('Kids')) : null;
          if (!kids) field.set(PDFName.of('Kids'), context.obj([ newAnnotRef ]));
          else if (kids.push) kids.push(newAnnotRef);
        } catch {}
        widgetRef = newAnnotRef;
        widget = context.lookup(widgetRef);
      }
    } catch {}
    // Last resort: if we still don't have a widgetRef, create one now
    if (!widgetRef) {
      try {
        const newAnnot = context.obj({ Type: 'Annot', Subtype: 'Widget', Rect:[newX1,newY1,newX2,newY2], P: targetPage.ref, F:4, Parent: fieldRef });
        widgetRef = context.register(newAnnot);
        widget = context.lookup(widgetRef);
        try {
          let kids = field.lookupMaybe ? field.lookupMaybe(PDFName.of('Kids')) : null;
          if (!kids) field.set(PDFName.of('Kids'), context.obj([ widgetRef ]));
          else if (kids.push) kids.push(widgetRef);
        } catch {}
      } catch {}
    }

    const esc = (s) => String(s).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
    const content = ['BT', `/F1 ${fontSize} Tf`, `1 0 0 1 ${padX} ${Math.max(0, h - padY - fontSize)} Tm`, `(${esc(line1Fit)}) Tj`, `1 0 0 1 ${padX} ${Math.max(0, h - padY - fontSize - lh)} Tm`, `(${esc(line2Fit)}) Tj`, 'ET'].join('\n');
    const apStream = context.stream(content, { Type:'XObject', Subtype:'Form', BBox:[0,0, Math.max(1,w), Math.max(1,h)], Matrix:[1,0,0,1,0,0], Resources:{ Font:{ F1: helv.ref } } });
    try { widget.set(PDFName.of('AP'), context.obj({ N: context.register(apStream) })); } catch {}
    try { const acro = pdfDoc2.catalog.lookup(PDFName.of('AcroForm')); acro.set(PDFName.of('SigFlags'), PDFNumber.of(3)); if (pdfDoc2.catalog.delete) pdfDoc2.catalog.delete(PDFName.of('NeedAppearances')); } catch {}
    // Ensure widget is attached ONLY to the target page (move from first page to last)
    try {
      // Set widget's /P to target page
      try { widget.set(PDFName.of('P'), targetPage.ref); } catch {}
      // Remove widget from Annots on all other pages; ensure present on target page
      const pages = pdfDoc2.getPages();
      for (let i = 0; i < pages.length; i++) {
        const pg = pages[i];
        try {
          let ann = pg.node.lookupMaybe ? pg.node.lookupMaybe(PDFName.of('Annots')) : null;
          let arr = [];
          if (ann) {
            if (ann.size && ann.get) { for (let j = 0; j < ann.size(); j++) arr.push(ann.get(j)); }
            else if (ann.array) { for (const r of ann.array) arr.push(r); }
          }
          // Filter out any accidental fieldRef entries and any existing widgetRef on non-target pages
          const filtered = [];
          for (const r of arr) {
            if (r === fieldRef) continue; // never keep field as annot
            if (i !== tIndex && r === widgetRef) continue; // drop widget from non-target pages
            filtered.push(r);
          }
          if (i === tIndex && widgetRef) filtered.push(widgetRef); // ensure present on target page
          if (filtered.length) pg.node.set(PDFName.of('Annots'), pdfDoc2.context.obj(filtered));
          else { try { pg.node.delete && pg.node.delete(PDFName.of('Annots')); } catch {} }
        } catch {}
      }
      // Verify target page Annots has the widget; if not, add it explicitly
      try {
        let annT = targetPage.node.lookupMaybe ? targetPage.node.lookupMaybe(PDFName.of('Annots')) : null;
        let items = [];
        if (annT) {
          if (annT.size && annT.get) { for (let j = 0; j < annT.size(); j++) items.push(annT.get(j)); }
          else if (annT.array) { for (const r of annT.array) items.push(r); }
        }
        let presentT = false;
        for (const r of items) { if (r === widgetRef) { presentT = true; break; } }
        if (!presentT && widgetRef) {
          items.push(widgetRef);
          targetPage.node.set(PDFName.of('Annots'), pdfDoc2.context.obj(items));
        }
      } catch {}
    } catch {}
    // Draw into page content too
    try {
      const yTopDraw = Math.max(0, newY1 + (newY2-newY1) - padY - fontSize);
      try { targetPage.drawRectangle({ x:newX1, y:newY1, width: Math.max(1,w), height: Math.max(1,h), color: rgb(1,1,1), opacity: 1, borderOpacity: 0 }); } catch {}
      try { targetPage.drawText(line1Fit, { x:newX1+padX, y:yTopDraw, size:fontSize, font:helv, color: rgb(0,0,0) }); } catch {}
      try { targetPage.drawText(line2Fit, { x:newX1+padX, y: Math.max(0, yTopDraw - lh), size:fontSize, font:helv, color: rgb(0,0,0) }); } catch {}
    } catch {}

  } catch {}

  return await pdfDoc2.save({ useObjectStreams: false });
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
          const b64 = s.replace(/-----(BEGIN|END)[^-]*-----/g, '').replace(/[\r\n\s]/g, '');
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
async function computeDynamicRect(pdfDoc, page, line1, line2, fontSize = 10, lh = 14, padX = 6, padY = 6, anchor = 'top-left', baseRect = [36, 36]) {
  const helv = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fitText = (t, maxW) => { let s = String(t); while (helv.widthOfTextAtSize(s, fontSize) > maxW && s.length > 1) s = s.slice(0, -1); return s; };
  const maxTextW = 300;
  const line1Fit = fitText(line1, maxTextW);
  const line2Fit = fitText(line2, maxTextW);
  const contentW = Math.max(helv.widthOfTextAtSize(line1Fit, fontSize), helv.widthOfTextAtSize(line2Fit, fontSize));
  const w = Math.ceil(contentW) + padX * 2;
  const h = (2 * fontSize) + (lh - fontSize) + padY * 2;
  let x1 = baseRect[0], y1 = baseRect[1];
  if (anchor === 'top-left') {
    // y1 is from bottom, so for top-left, we need to move down from the top
    const pageHeight = page.getHeight();
    y1 = pageHeight - y1 - h;
  }
  return [x1, y1, x1 + w, y1 + h];
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

// ...existing code...
app.post('/sign/pdf', requireAuth, async (req, res) => {
  try {
    const { dll } = ensureDllPicked();
    let pin = (req.body && req.body.pin) || DSC_PIN_ENV || '';
    if (!pin && SESSION_PIN) pin = SESSION_PIN;
    let requirePin = (req.body && req.body.requirePin === true) || REQUIRE_PIN_PER_SIGN;
    if (SESSION_PIN && !(req.body && req.body.requirePin === true)) requirePin = false;
    if (requirePin) {
      try {
        pin = await promptPinInteractive('Enter token PIN to sign');
        if (req.body && req.body.rememberSessionPin === true && pin) SESSION_PIN = String(pin);
      } catch (e) {
        return res.status(400).json({ ok: false, message: e.message || 'PIN required' });
      }
    }
    if (req.body && req.body.rememberSessionPin === false) SESSION_PIN = '';
    const b64 = req.body && req.body.pdfBase64;
    if (!b64) return res.status(400).json({ ok:false, message: 'pdfBase64 missing' });
    const reason = (req.body && req.body.reason) || 'Signed via DSC Agent';
    const includeESS = req.body && req.body.includeESS !== undefined ? !!req.body.includeESS : true;
    const embedIntermediates = req.body && req.body.embedIntermediates !== undefined ? !!req.body.embedIntermediates : false;
    const signingTime = parseLocalTime(req.body && req.body.signingTime);
    const stampAllPages = !!(req.body && req.body.stampAllPages === true);
    const rectOverride = (req.body && Array.isArray(req.body.rect) && (req.body.rect.length === 4 || req.body.rect.length === 2))
      ? req.body.rect.map((n) => parseInt(n, 10))
      : null;
    const anchor = (req.body && typeof req.body.anchor === 'string') ? String(req.body.anchor).toLowerCase() : 'top-left';
  const pageReq = req.body && req.body.page;
  // Always use 'last' if no page is specified, to default to last page
  const requestedPageIndex = (pageReq === undefined || pageReq === null || pageReq === '' || pageReq === 'last') ? 'last' : normalizeRequestedPageIndex(pageReq);

    const inputBuf = Buffer.from(b64, 'base64');
    assertNoExistingSignature(inputBuf);

    // Detect signer cert first
    const { idHex, certDER } = detectSigningKey(dll, pin);
    const asn = asn1js.fromBER(ab(certDER));
    const signerCert = new pkijs.Certificate({ schema: asn.result });

    const intermediates = await fetchIntermediatesIfRequested(signerCert, embedIntermediates);
    const userName = signerCert.subject.typesAndValues.find(tv => tv.type === '2.5.4.3')?.value.valueBlock.value || 'Unknown';

    // Compose the signature text for dynamic sizing
    const pad = (n) => String(n).padStart(2, '0');
    const dt = signingTime || new Date();
    const tsText = `${dt.getFullYear()}-${pad(dt.getMonth()+1)}-${pad(dt.getDate())} ${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`;
    const line1 = `Digitally signed by ${userName}`;
    const line2 = `Date: ${tsText}`;
    const fontSize = 10, lh = 14, padX = 6, padY = 6;

    // --- Dynamically calculate widget rect to fit text on the correct page ---
    let widgetRect = rectOverride || SIGN_RECT;
    try {
      const pdfDoc = await PDFDocument.load(inputBuf);
      const pageCount = pdfDoc.getPageCount();
      const targetIndex = (requestedPageIndex === 'last') ? (pageCount - 1)
        : (requestedPageIndex && requestedPageIndex > 0 ? Math.min(pageCount - 1, requestedPageIndex - 1) : 0);
      const targetPage = pdfDoc.getPages()[targetIndex];
      // If no rectOverride, place at bottom right
      if (!rectOverride) {
        // Compute dynamic width/height
        const helv = await pdfDoc.embedFont(StandardFonts.Helvetica);
        const fitText = (t, maxW) => { let s = String(t); while (helv.widthOfTextAtSize(s, fontSize) > maxW && s.length > 1) s = s.slice(0, -1); return s; };
        const maxTextW = 300;
        const line1Fit = fitText(line1, maxTextW);
        const line2Fit = fitText(line2, maxTextW);
        const contentW = Math.max(helv.widthOfTextAtSize(line1Fit, fontSize), helv.widthOfTextAtSize(line2Fit, fontSize));
        const w = Math.ceil(contentW) + padX * 2;
        const h = (2 * fontSize) + (lh - fontSize) + padY * 2;
        const pageWidth = targetPage.getWidth();
        const pageHeight = targetPage.getHeight();
        const x1 = pageWidth - w - 36; // 36pt margin from right
        const y1 = 36; // 36pt margin from bottom
        widgetRect = [x1, y1, x1 + w, y1 + h];
      } else {
        widgetRect = await computeDynamicRect(pdfDoc, targetPage, line1, line2, fontSize, lh, padX, padY, anchor, rectOverride || [36, 36]);
      }
    } catch (e) {
      widgetRect = rectOverride || SIGN_RECT;
    }

    // --- Use the robust batch logic for stamping and widget placement ---
    // Always pass 'last' as requestedPageIndex unless a specific page is requested
    let prepared = await buildPlaceholderWithVisibleStamp(
      inputBuf,
      userName,
      reason,
      signingTime,
      widgetRect,      // dynamic rect
      'pdf',           // rectMode
      anchor,
      requestedPageIndex, // 'last' by default
      stampAllPages
    );

    // --- Move the widget annotation to the correct page (last by default) ---
    try {
      const pdfDoc = await PDFDocument.load(prepared);
      const pageCount = pdfDoc.getPageCount();
      let targetIndex = 0;
      if (requestedPageIndex === 'last') {
        targetIndex = pageCount - 1;
      } else if (typeof requestedPageIndex === 'number' && requestedPageIndex > 0) {
        targetIndex = Math.min(pageCount - 1, requestedPageIndex - 1);
      }
      // Find the widget annotation
      const acroForm = pdfDoc.catalog.lookup(PDFName.of('AcroForm'));
      const fields = acroForm.lookup(PDFName.of('Fields'));
      const fieldRef = fields.get(fields.size() - 1);
      const field = pdfDoc.context.lookup(fieldRef);
      let widgetRef = null;
      let widget = null;
      try {
        const kids = field.lookup(PDFName.of('Kids'));
        widgetRef = kids && (kids.get ? kids.get(0) : (kids.array ? kids.array[0] : null));
        if (widgetRef) widget = pdfDoc.context.lookup(widgetRef);
      } catch {}
      if (!widget) { widgetRef = fieldRef; widget = field; }

      // Remove widget from all pages
      for (let i = 0; i < pageCount; ++i) {
        const page = pdfDoc.getPages()[i];
        const annots = page.node.Annots();
        if (annots) {
          const arr = annots.asArray();
          const idx = arr.findIndex(ref => ref === widgetRef);
          if (idx !== -1) {
            arr.splice(idx, 1);
            page.node.set(PDFName.of('Annots'), pdfDoc.context.obj(arr));
          }
        }
      }
      // Add widget to the correct page
      const targetPage = pdfDoc.getPages()[targetIndex];
      let annots = targetPage.node.Annots();
      let arr = annots ? annots.asArray() : [];
      arr.push(widgetRef);
      targetPage.node.set(PDFName.of('Annots'), pdfDoc.context.obj(arr));
      prepared = await pdfDoc.save({ useObjectStreams: false });
    } catch (moveErr) {
      console.warn('Failed to move widget annotation:', moveErr.message || moveErr);
    }

    const signer = new TokenSigner({ dll, pin, signerCert, intermediates, includeESS, signingTime });
    const signedPdf = await new SignPdf().sign(prepared, signer);
    res.json({ ok:true, signedPdfBase64: signedPdf.toString('base64') });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false, message: e.message });
  }
});

// ...existing code...
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
