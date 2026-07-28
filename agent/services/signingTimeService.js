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
  const response = error && error.response ? error.response : null;
  if (response && response.error && response.error.message) return String(response.error.message);
  if (response && response.error && response.error.msg) return String(response.error.msg);
  if (response && response.msg) return String(response.msg);
  if (response && response.message) return String(response.message);
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

  const apiKey = toTrimmedString(params.payload.apiKey);
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
      endpoint: params.endpoint || '/api/time',
      timeoutMs: 5000,
      retries: 0,
    });

    // Accept signingTime from multiple common response field names
    const rawSigningTime = (response && response.server_time) || null;
    
    // Also check the configured time field name from deps
    const configuredField = deps && deps.timeField;
    const rawFromConfigField = configuredField && response ? response[configuredField] : null;
    const resolvedRaw = (configuredField && rawFromConfigField) ? rawFromConfigField : rawSigningTime;
    const signingTime = parseSigningTime(resolvedRaw, deps.parseLocalTime);
    if (!signingTime) {
      const fields = response ? Object.keys(response).join(', ') : 'empty response';
      const err = new Error(`Authorization response is missing a valid signingTime. Received fields: ${fields}`);
      err.status = 502;
      throw err;
    }

    return {
      signingTime,
      raw: response,
    };
  } catch (error) {
    const err = new Error(extractRemoteErrorMessage(error, 'Unable to create signing authorization.'));
    if (error && typeof error.status === 'number') err.status = error.status;
    if (error && error.response) err.response = error.response;
    console.log('err ', err)
    throw err;
  }
}

module.exports = {
  createSigningAuthorization,
};
