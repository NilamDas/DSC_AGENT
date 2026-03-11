async function runTimeServerHealthOnBoot(timeServerClient) {
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
