# Future Recommendations

This document outlines potential improvements for the DSC Agent application. These are recommendations only and are not part of the current implementation.

## 1. Connected-Token Detection

- Distinguish between an installed PKCS#11 driver and a physically connected token.
- Show connection status for every supported token vendor.
- Refresh the status automatically when a token is inserted or removed.

## 2. Automatic Vendor Switching

- Detect another connected token when the currently selected token is removed.
- Select the appropriate vendor DLL automatically when only one token is connected.
- Require user confirmation when multiple connected tokens are available.
- Never switch tokens during an active signing operation.

## 3. Token and Certificate Information

- Display the token vendor, model, label, and serial number.
- Display the certificate holder, issuer, validity period, and expiry status.
- Warn users when a certificate is expired or close to expiry.
- Clearly identify which certificate will be used for signing.

## 4. Startup Readiness

- Keep the interface in a clear `Starting` state until the agent is listening.
- Verify that the PIN prompt server and renderer are ready before accepting signing requests.
- Show separate readiness states for the agent, token, certificate, and time server.
- Provide actionable messages when startup fails.

## 5. Diagnostics and Support

- Add a diagnostics screen containing:
  - Agent and application versions
  - Agent and PIN-server status
  - Selected token vendor and DLL path
  - Token connection status
  - Listening ports
  - Bundled Node.js version
  - Recent application and agent errors
- Allow users to export a sanitized diagnostic report for support.
- Exclude PINs, authentication tokens, and sensitive document information from reports.

## 6. Signing Performance Metrics

- Record separate timings for:
  - PDF loading and parsing
  - Token discovery
  - PIN entry and token login
  - Certificate and key discovery
  - Cryptographic signing
  - Timestamping and LTV processing
  - PDF writing and response transfer
- Use these metrics to identify whether delays come from the application, token driver, network, or PDF processing.

## 7. Large-File Handling

- Reduce unnecessary PDF buffer copies.
- Release large buffers as soon as they are no longer required.
- Consider temporary-file or streaming workflows for very large PDFs.
- Add configurable file-size and memory limits.
- Report upload, processing, and signing progress for long operations.

## 8. Automatic Recovery

- Restart the agent after an unexpected crash with a controlled retry policy.
- Recover cleanly from token removal, stale PKCS#11 sessions, renderer crashes, and PIN-window failures.
- Prevent restart loops by applying retry limits and backoff delays.
- Ensure abandoned operations release timers, listeners, sessions, and pending responses.

## 9. Cross-Platform Automated Testing

- Test protected and development builds separately.
- Cover Windows, macOS, and Linux where supported.
- Include automated tests for:
  - First startup and automatic agent start
  - Token detection and vendor selection
  - Single and batch signing
  - Text signing
  - Re-signing and flattening
  - PIN submission, cancellation, timeout, and retry
  - Token removal before and during signing
  - Large PDF processing
  - Renderer and agent crash recovery

## 10. Vendor Compatibility

- Maintain tested profiles for supported vendors such as ProxKey, ePass, HYP, SafeNet, Watchdata, and OpenSC.
- Record verified driver versions and operating-system compatibility.
- Support vendor-specific DLL locations through configuration.
- Provide a controlled custom-DLL option for unsupported vendors.

## 11. Security Hardening

- Protect stored configuration and authentication tokens using operating-system credential storage.
- Restrict permissions on configuration and log files.
- Verify the integrity of bundled runtimes and protected application resources.
- Digitally sign Windows and Linux packages where applicable.
- Sign and notarize macOS packages.
- Avoid logging PINs, PDF contents, authentication headers, or private certificate data.

## 12. Safe Updates and Rollback

- Distribute only signed application updates.
- Verify update integrity before installation.
- Preserve the last known working version for quick rollback.
- Back up compatible user settings before an upgrade.
- Provide clear release notes and migration information.

## Suggested Priority

1. Connected-token detection and automatic recovery
2. Startup readiness and diagnostics
3. Cross-platform and vendor compatibility testing
4. Signing performance measurement and large-file optimization
5. Security hardening
6. Signed updates and rollback support

