const crypto = require('crypto');

function toBuffer(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (value && value.buffer && value.byteLength !== undefined) {
    return Buffer.from(value.buffer, value.byteOffset || 0, value.byteLength);
  }
  return Buffer.from(value || []);
}

function toTrimmedString(value) {
  if (value === undefined || value === null) return '';
  return String(value).trim();
}

function normalizeSignerIdentity(identity = {}) {
  return {
    name: toTrimmedString(identity.name),
    machineHash: toTrimmedString(identity.machineHash),
  };
}

function computeSha256Hex(value) {
  return crypto.createHash('sha256').update(toBuffer(value)).digest('hex');
}

function toIsoString(value, fieldName) {
  const dt = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(dt.getTime())) {
    throw new Error(`${fieldName} must be a valid date`);
  }
  return dt.toISOString();
}

function buildCreateAuthorizationPayload({ requestId, sourceBuffer, signerIdentity }) {
  const signer = normalizeSignerIdentity(signerIdentity);
  const normalizedRequestId = toTrimmedString(requestId);
  const sourceSha256 = computeSha256Hex(sourceBuffer);

  if (!normalizedRequestId) throw new Error('requestId is required');
  if (!signer.name) throw new Error('signer.name is required');
  if (!signer.machineHash) throw new Error('signer.machineHash is required');
  if (!sourceSha256) throw new Error('document.sourceSha256 is required');

  return {
    requestId: normalizedRequestId,
    signer,
    document: {
      sourceSha256,
    },
  };
}

function buildCompletionPayload({
  authorizationToken,
  status = 'completed',
  failureReason,
  sourceBuffer,
  signedBuffer,
  signerIdentity,
  signingTime,
  signedAt,
}) {
  const normalizedStatus = toTrimmedString(status);
  const token = toTrimmedString(authorizationToken);

  if (!token) throw new Error('authorizationToken is required');
  if (!normalizedStatus) throw new Error('status is required');

  const payload = {
    status: normalizedStatus,
    authorizationToken: token,
  };

  if (normalizedStatus !== 'completed') {
    if (failureReason) payload.failureReason = toTrimmedString(failureReason);
    return payload;
  }

  const signer = normalizeSignerIdentity(signerIdentity);
  const resultSigningTime = toIsoString(signingTime, 'result.signingTime');
  const resultSignedAt = toIsoString(signedAt, 'result.signedAt');

  if (!signer.machineHash) throw new Error('result.machineHash is required');

  payload.result = {
    sourceSha256: computeSha256Hex(sourceBuffer),
    machineHash: signer.machineHash,
    signingTime: resultSigningTime,
    signedAt: resultSignedAt,
    finalDocumentSha256: computeSha256Hex(signedBuffer),
  };

  return payload;
}

module.exports = {
  buildCreateAuthorizationPayload,
  buildCompletionPayload,
  computeSha256Hex,
  normalizeSignerIdentity,
};
