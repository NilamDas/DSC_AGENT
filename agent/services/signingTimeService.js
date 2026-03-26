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

function toTrimmedString(value) {
  if (value === undefined || value === null) return '';
  return String(value).trim();
}

function extractRemoteErrorMessage(error, fallback) {
  if (error && error.response && error.response.error && error.response.error.message) {
    return String(error.response.error.message);
  }
  if (error && error.message) return String(error.message);
  return fallback;
}

async function createSigningAuthorization(params = {}, deps = {}) {
  const timeServerClient = deps && deps.timeServerClient;
  if (!timeServerClient || typeof timeServerClient.createAuthorization !== 'function') {
    const err = new Error('Time server client is unavailable. Signing authorization cannot be created.');
    err.status = 500;
    throw err;
  }

  const apiKey = toTrimmedString(params.apiKey);
  const payload = params.payload && typeof params.payload === 'object' ? params.payload : null;

  if (!apiKey) {
    const err = new Error('API key is required for signing authorization.');
    err.status = 400;
    throw err;
  }
  
  if (!payload) {
    const err = new Error('Authorization payload is required.');
    err.status = 400;
    throw err;
  }

  try {
    const response = await timeServerClient.createAuthorization(apiKey, payload, {
      endpoint: '/api/sign/authorizations',
      timeoutMs: 5000,
      retries: 0,
    });

    const signingTime = parseSigningTime(response && response.signingTime, deps.parseLocalTime);
    if (!signingTime) {
      const err = new Error('Authorization response is missing a valid signingTime.');
      err.status = 502;
      throw err;
    }

    return {
      authorizationId: toTrimmedString(response && response.authorizationId),
      authorizationToken: toTrimmedString(response && response.authorizationToken),
      requestId: toTrimmedString(response && response.requestId),
      decision: toTrimmedString(response && response.decision),
      signingTime,
      expiresAt: toTrimmedString(response && response.expiresAt),
      bind: response && typeof response.bind === 'object' ? response.bind : {},
      remaining: response && response.remaining,
      raw: response,
    };
  } catch (error) {
    const err = new Error(extractRemoteErrorMessage(error, 'Unable to create signing authorization.'));
    if (error && typeof error.status === 'number') err.status = error.status;
    if (error && error.response) err.response = error.response;
    throw err;
  }
}

async function completeSigningAuthorization(params = {}, deps = {}) {
  const timeServerClient = deps && deps.timeServerClient;
  if (!timeServerClient || typeof timeServerClient.completeAuthorization !== 'function') {
    const err = new Error('Time server client is unavailable. Signing authorization cannot be completed.');
    err.status = 500;
    throw err;
  }

  const apiKey = toTrimmedString(params.apiKey);
  const authorizationId = toTrimmedString(params.authorizationId);
  const payload = params.payload && typeof params.payload === 'object' ? params.payload : null;

  if (!apiKey) {
    const err = new Error('API key is required for signing completion.');
    err.status = 400;
    throw err;
  }
  if (!authorizationId) {
    const err = new Error('authorizationId is required for signing completion.');
    err.status = 400;
    throw err;
  }
  if (!payload) {
    const err = new Error('Completion payload is required.');
    err.status = 400;
    throw err;
  }

  try {
    return await timeServerClient.completeAuthorization(apiKey, authorizationId, payload, {
      timeoutMs: 5000,
      retries: 0,
    });
  } catch (error) {
    const err = new Error(extractRemoteErrorMessage(error, 'Unable to complete signing authorization.'));
    if (error && typeof error.status === 'number') err.status = error.status;
    if (error && error.response) err.response = error.response;
    throw err;
  }
}

module.exports = {
  createSigningAuthorization,
  completeSigningAuthorization,
};
