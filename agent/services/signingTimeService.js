function parseSigningTime(value, parseLocalTime) {
  if (!value) return null;

  if (typeof value === 'string') {
    const raw = value.trim();
    if (!raw) return null;

    const iso = new Date(raw);
    if (!Number.isNaN(iso.getTime())) return iso;

    try {
      return parseLocalTime(raw);
    } catch {
      return null;
    }
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    const millis = value > 1e12 ? value : value * 1000;
    const dt = new Date(millis);
    if (!Number.isNaN(dt.getTime())) return dt;
  }

  return null;
}

function hasCompleteUser(user) {
  return !!(user && user.name && user.machineHash);
}

function toTrimmedString(value) {
  if (value === undefined || value === null) return '';
  return String(value).trim();
}

function resolveUserFromBody(reqBody = {}) {
  const body = reqBody && typeof reqBody === 'object' ? reqBody : {};
  const name = toTrimmedString(body.name);
  const machineHash = toTrimmedString(body.machineHash);
  const apiKey = toTrimmedString(body.apiKey);

  return { name, machineHash, apiKey };
}

function resolveUser(reqBody = {}) {
  return resolveUserFromBody(reqBody);
}

function decodeJwtPayload(token) {
  try {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length < 2) return null;
    const normalized = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
    const json = Buffer.from(padded, 'base64').toString('utf8');
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function extractToken(tokenResponse) {
  if (!tokenResponse || typeof tokenResponse !== 'object') return '';
  if (typeof tokenResponse.token === 'string') return tokenResponse.token;
  if (typeof tokenResponse.jwt === 'string') return tokenResponse.jwt;
  if (typeof tokenResponse.accessToken === 'string') return tokenResponse.accessToken;
  if (tokenResponse.data && typeof tokenResponse.data.token === 'string') return tokenResponse.data.token;
  if (tokenResponse.data && typeof tokenResponse.data.jwt === 'string') return tokenResponse.data.jwt;
  return '';
}

function getTokenExpMs(token) {
  const payload = decodeJwtPayload(token);
  if (!payload || typeof payload.exp !== 'number') return 0;
  return payload.exp * 1000;
}

async function requestFreshToken(user, timeServerClient) {
  if (!timeServerClient || typeof timeServerClient.generateToken !== 'function') return null;
  const tokenRes = await timeServerClient.generateToken(user, {
    endpoint: '/api/auth/generate-token',
    timeoutMs: 5000,
    retries: 1,
  });
  const token = extractToken(tokenRes);
  if (!token) throw new Error('No token returned from /api/auth/generate-token');
  return {
    token,
    expiresAtMs: getTokenExpMs(token),
    fetchedAtMs: Date.now(),
    user,
  };
}

async function resolveSigningContextFromTimeServerOrBody(reqBody, deps) {
  const parseLocalTime = deps && deps.parseLocalTime;
  const timeServerClient = deps && deps.timeServerClient;
  if (typeof parseLocalTime !== 'function') {
    throw new Error('resolveSigningContextFromTimeServerOrBody requires parseLocalTime function');
  }

  if (!timeServerClient || typeof timeServerClient.requestTimestamp !== 'function') {
    throw new Error('Time server client is unavailable. Signing requires server timestamp.');
  }

  const user = resolveUser(reqBody);
  
  console.log(`user api key is ${user.apiKey}`);

  console.log('user info for time server request:', {
    name: user.name,
    machineHash: user.machineHash,
    apiKey: user.apiKey
  });

  const canUseRemote = hasCompleteUser(user);
  let signingTime = null;
  let token = null;
  const usedCachedToken = false;

  if (!canUseRemote) {
    throw new Error('User name and token serial (machineHash) are required in request body to fetch signing timestamp.');
  }

  try {
    const ts = await timeServerClient.requestTimestamp(user, { endpoint: '/api/time', timeoutMs: 5000, retries: 0 });
    const value = (ts && (ts.server_time)) || null;
    const parsed = parseSigningTime(value, parseLocalTime);
    if (!parsed) {
      throw new Error('Invalid or missing server_time in /api/time response.');
    }
    signingTime = parsed;
    console.log('[time-server] resolved timestamp:', value, '=>', signingTime);
  } catch (e) {
    const err = new Error(`Failed to fetch server timestamp from /api/time: ${e && e.message ? e.message : String(e)}`);
    if (e && typeof e.status === 'number') err.status = e.status;
    throw err;
  }

  try {
    const entry = await requestFreshToken(user, timeServerClient);
    token = entry && entry.token ? entry.token : null;
    if (!token) {
      throw new Error('No token returned from /api/auth/generate-token');
    }
    console.log('[time-server] token generated for this signing request.');
  } catch (e) {
    const err = new Error(`/api/auth/generate-token failed: ${e && e.message ? e.message : String(e)}`);
    if (e && typeof e.status === 'number') err.status = e.status;
    throw err;
  }

  return {
    signingTime,
    token,
    user,
    usedCachedToken,
    source: 'server',
  };
}

async function authorizeServerSignOrBypass(reqBody, deps, signingContext = {}) {
  const timeServerClient = deps && deps.timeServerClient;
  const strict = String(process.env.TIMESERVER_SIGN_AUTH_STRICT || '0') === '1';

  if (!timeServerClient || typeof timeServerClient.requestSignAuthorization !== 'function') {
    return { ok: true, bypassed: true, reason: 'no-client-method' };
  }

  const user = signingContext.user || resolveUser(reqBody);

  let token = signingContext.token || '';

  // if (!token && hasCompleteUser(user)) {
  //   try {
  //     const entry = await requestFreshToken(user, timeServerClient);
  //     token = entry && entry.token ? entry.token : '';
  //   } catch (tokenErr) {
  //     if (strict) throw tokenErr;
  //     console.log('[time-server] token generation failed before /api/sign. Continuing in non-strict mode. Error:', tokenErr && tokenErr.message ? tokenErr.message : tokenErr);
  //     token = '';
  //   }
  // }

  if (!token) {
    if (strict) throw new Error('Missing auth token for /api/sign authorization');
    return { ok: true, bypassed: true, reason: 'no-token' };
  }

  const authPayload = {
    name: user.name,
    machineHash: user.machineHash,
    intent: 'pdf-sign',
  };

  try {
    const response = await timeServerClient.requestSignAuthorization(token, authPayload, {
      endpoint: '/api/sign',
      timeoutMs: 5000,
      retries: 0,
    });
    return { ok: true, bypassed: false, response };
  } catch (e) {
    const status = e && typeof e.status === 'number' ? e.status : 0;
    const tokenRejected = status === 401 || status === 403;

    if (!tokenRejected || !hasCompleteUser(user)) {
      if (strict) throw e;
      console.log('[time-server] /api/sign auth check failed. Continuing in non-strict mode. Error:', e && e.message ? e.message : e);
      return { ok: false, bypassed: true, reason: 'non-strict-failure', error: e };
    }

    try {
      const refreshed = await requestFreshToken(user, timeServerClient);
      const refreshedToken = refreshed && refreshed.token ? refreshed.token : '';
      if (!refreshedToken) throw new Error('Token refresh did not return a token');

      const retryResponse = await timeServerClient.requestSignAuthorization(refreshedToken, authPayload, {
        endpoint: '/api/sign',
        timeoutMs: 5000,
        retries: 0,
      });

      return { ok: true, bypassed: false, response: retryResponse, refreshed: true };
    } catch (refreshErr) {
      if (strict) throw refreshErr;
      console.log('[time-server] /api/sign retry after token refresh failed. Continuing in non-strict mode. Error:', refreshErr && refreshErr.message ? refreshErr.message : refreshErr);
      return { ok: false, bypassed: true, reason: 'retry-failed', error: refreshErr };
    }
  }
}

async function resolveSigningTimeFromTimeServerOrBody(reqBody, deps) {
  const context = await resolveSigningContextFromTimeServerOrBody(reqBody, deps);
  return context.signingTime;
}

module.exports = {
  resolveSigningTimeFromTimeServerOrBody,
  resolveSigningContextFromTimeServerOrBody,
  authorizeServerSignOrBypass,
};
