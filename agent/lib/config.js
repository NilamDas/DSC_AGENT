const fs = require('fs');
const path = require('path');

function parseSignRect(v) {
  const arr = String(v || '250,40,600,90').split(',').map(n => parseInt(String(n).trim(), 10));
  if (!Array.isArray(arr) || arr.length !== 4 || arr.some(n => Number.isNaN(n))) {
    throw new Error('Invalid DSC_SIGN_RECT. Use "x1,y1,x2,y2" (e.g., 50,700,350,780)');
  }
  return arr;
}

function loadJsonConfig() {
  try {
    const overridePath = process.env.DSC_CONFIG_PATH && process.env.DSC_CONFIG_PATH.trim();
    const candidates = [];
    if (overridePath) candidates.push(overridePath);
    // Relative to this file's location (works regardless of CWD, e.g. when spawned from electron-app/)
    candidates.push(path.join(__dirname, '..', '..', 'dsc-agent.config.json'));
    candidates.push(path.join(__dirname, '..', '..', 'agent.config.json'));
    // project root relative files
    candidates.push(path.join(process.cwd(), 'dsc-agent.config.json'));
    candidates.push(path.join(process.cwd(), 'agent.config.json'));
    // agent folder fallback
    candidates.push(path.join(process.cwd(), 'agent', 'dsc-agent.config.json'));
    for (const p of candidates) {
      try { if (p && fs.existsSync(p)) { const raw = fs.readFileSync(p, 'utf8'); return JSON.parse(raw); } } catch {}
    }
  } catch {}
  return {};
}

const fileCfg = loadJsonConfig();

const DEFAULT_CANDIDATES = [
  // Windows
  'C:/Windows/System32/SignatureP11.dll',
  'C:/Windows/SysWOW64/SignatureP11.dll',
  'C:/Windows/System32/eps2003csp11.dll',
  'C:/Windows/SysWOW64/eps2003csp11.dll',
  'C:/Windows/System32/eps2003csp11v2.dll',
  'C:/Windows/SysWOW64/eps2003csp11v2.dll',
  'C:/Program Files/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll',
  'C:/Program Files (x86)/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll',
  'C:/Windows/System32/eTPKCS11.dll',
  'C:/Windows/SysWOW64/eTPKCS11.dll',
  'C:/Windows/System32/CryptoIDA_pkcs11.dll',
  'C:/Windows/SysWOW64/CryptoIDA_pkcs11.dll',
  // macOS
  '/Library/OpenSC/lib/opensc-pkcs11.so',
  '/usr/local/lib/opensc-pkcs11.so',
  '/usr/local/lib/libeTPkcs11.dylib',
  '/Library/Frameworks/eToken.framework/Versions/Current/eToken',
  '/usr/local/lib/libeps2003csp11.dylib',
  '/usr/local/lib/libwdpkcs.dylib',
  // Linux
  '/usr/lib/opensc-pkcs11.so',
  '/usr/local/lib/opensc-pkcs11.so',
  '/usr/lib64/opensc-pkcs11.so',
  '/usr/local/lib64/opensc-pkcs11.so',
  '/usr/lib/libeTPkcs11.so',
  '/usr/local/lib/libeTPkcs11.so',
  '/usr/lib/libeps2003csp11.so',
  '/usr/local/lib/libeps2003csp11.so',
  '/usr/lib/libwdpkcs.so',
  '/usr/local/lib/libwdpkcs.so',
  '/usr/lib/libSignatureP11.so',
  '/usr/local/lib/libSignatureP11.so',
];

const cfg = Object.freeze({
  DEFAULT_CANDIDATES,
  KNOWN_TOKENS: {
    'ProxKey': {
      name: 'ProxKey',
      paths: [
        'C:/Windows/System32/SignatureP11.dll',
        'C:/Windows/SysWOW64/SignatureP11.dll',
        '/usr/lib/libSignatureP11.so',
        '/usr/local/lib/libSignatureP11.so',
        '/usr/local/lib/libSignatureP11.dylib',
      ],
    },
    'ePass2003': {
      name: 'ePass2003',
      paths: [
        'C:/Windows/System32/eps2003csp11.dll',
        'C:/Windows/SysWOW64/eps2003csp11.dll',
        '/usr/lib/libeps2003csp11.so',
        '/usr/local/lib/libeps2003csp11.so',
        '/usr/local/lib/libeps2003csp11.dylib',
      ],
    },
    'HYP 2003': {
      name: 'HYP 2003',
      paths: [
        'C:/Windows/System32/eps2003csp11v2.dll',
        'C:/Windows/SysWOW64/eps2003csp11v2.dll',
        '/usr/lib/libeps2003csp11v2.so',
        '/usr/local/lib/libeps2003csp11v2.so',
        '/usr/local/lib/libeps2003csp11v2.dylib',
      ],
    },
    'SafeNet eToken': {
      name: 'SafeNet eToken',
      paths: [
        'C:/Windows/System32/eTPKCS11.dll',
        'C:/Windows/SysWOW64/eTPKCS11.dll',
        '/usr/lib/libeTPkcs11.so',
        '/usr/local/lib/libeTPkcs11.so',
        '/usr/local/lib/libeTPkcs11.dylib',
        '/Library/Frameworks/eToken.framework/Versions/Current/eToken',
      ],
    },
    'OpenSC': {
      name: 'OpenSC',
      paths: [
        'C:/Program Files/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll',
        'C:/Program Files (x86)/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll',
        '/Library/OpenSC/lib/opensc-pkcs11.so',
        '/usr/local/lib/opensc-pkcs11.so',
        '/usr/lib/opensc-pkcs11.so',
        '/usr/lib64/opensc-pkcs11.so',
        '/usr/local/lib64/opensc-pkcs11.so',
      ],
    },
    'Watchdata (mToken)': {
      name: 'Watchdata (mToken)',
      paths: [
        'C:/Windows/System32/wdpkcs.dll',
        'C:/Windows/SysWOW64/wdpkcs.dll',
        '/usr/lib/libwdpkcs.so',
        '/usr/local/lib/libwdpkcs.so',
        '/usr/local/lib/libwdpkcs.dylib',
      ],
    },
  },
  PKCS11_DLL: process.env.PKCS11_DLL || (fileCfg.pkcs11Dll || ''),
  DSC_PIN_ENV: process.env.DSC_PIN || (fileCfg.pin || ''),
  PORT: parseInt(process.env.DSC_AGENT_PORT || String(fileCfg.port || '18080'), 10),
  ALLOW: (() => {
    const fromEnv = process.env.ALLOW_ORIGINS;
    if (fromEnv && fromEnv.trim()) return fromEnv.split(',').map(s => s.trim());
    if (Array.isArray(fileCfg.allowOrigins)) return fileCfg.allowOrigins.map(s => String(s).trim());
    if (typeof fileCfg.allowOrigins === 'string') return String(fileCfg.allowOrigins).split(',').map(s => s.trim());
    return '*'.split(',');
  })(),
  AUTH_TOKEN: process.env.DSC_AUTH_TOKEN || (fileCfg.authToken || ''),
  ALLOW_LOCAL_SHUTDOWN: String(process.env.DSC_ALLOW_SHUTDOWN || String(fileCfg.allowLocalShutdown ? 1 : 0)) === '1',
  REQUIRE_PIN_PER_SIGN: String(process.env.DSC_REQUIRE_PIN_PER_SIGN || String(fileCfg.requirePinPerSign ? 1 : 0)) === '1',
  PIN_PROMPT_URL: process.env.DSC_PIN_PROMPT_URL || ((fileCfg.pinPrompt && fileCfg.pinPrompt.url) || ''),
  PIN_PROMPT_TOKEN: process.env.DSC_PIN_PROMPT_TOKEN || ((fileCfg.pinPrompt && fileCfg.pinPrompt.token) || ''),
  SIGN_RECT: (() => {
    const envRect = process.env.DSC_SIGN_RECT;
    if (envRect && envRect.trim()) return parseSignRect(envRect);
    if (Array.isArray(fileCfg.signRect)) return parseSignRect(fileCfg.signRect.join(','));
    if (typeof fileCfg.signRect === 'string') return parseSignRect(fileCfg.signRect);
    return parseSignRect();
  })(),
  MAX_BODY_MB: parseInt(process.env.DSC_MAX_BODY_MB || String(fileCfg.maxBodyMb || '100'), 10),
  LTV_ENABLE: String(process.env.DSC_LTV || String(fileCfg.ltv ? 1 : 0)) === '1',
  LTV_STRICT: String(process.env.DSC_LTV_STRICT || String(fileCfg.ltvStrict ? 1 : 0)) === '1',
  TIME_SERVER_URL: process.env.DSC_TIME_SERVER_URL || (fileCfg.timeServerUrl || ''),
  TIME_SERVER_ENDPOINT: process.env.DSC_TIME_SERVER_ENDPOINT || (fileCfg.timeServerEndpoint || ''),
  TIME_SERVER_METHOD: process.env.DSC_TIME_SERVER_METHOD || (fileCfg.timeServerMethod || 'GET'),
  TIME_SERVER_TIME_FIELD: process.env.DSC_TIME_SERVER_TIME_FIELD || (fileCfg.timeServerTimeField || 'time'),
  TIME_SERVER_ALLOW_SELF_SIGNED: String(process.env.DSC_TIME_SERVER_ALLOW_SELF_SIGNED || String(fileCfg.timeServerAllowSelfSigned ? 1 : 0)) === '1',
});

module.exports = cfg;
