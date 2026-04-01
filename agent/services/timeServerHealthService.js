async function runTimeServerHealthOnBoot(timeServerClient, options = {}) {
  if (options && options.skip) {
    console.log('[time-server] health check skipped (custom time server configured)');
    return;
  }
  try {
    const health = await timeServerClient.checkHealth({ timeoutMs: 2000, retries: 1 });
    console.log('[time-server] health OK:', health);
  } catch (err) {
    console.warn('[time-server] health FAILED:', err && err.message ? err.message : err);
  }
}

module.exports = {
  runTimeServerHealthOnBoot,
};
