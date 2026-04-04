const crypto = require('crypto');
const os = require("os");

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

function buildCreateAuthorizationPayload({ signerIdentity, remoteApiKey }) {
  const signer = normalizeSignerIdentity(signerIdentity);

  if (!signer.name) throw new Error('signer.name is required');
  if (!signer.machineHash) throw new Error('signer.machineHash is required');
  if (!remoteApiKey) throw new Error('Api key is required for signing');

  const name = signer.name;
  const machineHash = signer.machineHash;
  const apiKey = remoteApiKey;
  const osPlatform = os.platform();

  return {
    name,
    machineHash,
    apiKey,
    osPlatform
  };
}



module.exports = {
  buildCreateAuthorizationPayload,
  normalizeSignerIdentity,
};
