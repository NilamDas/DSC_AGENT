# DSC Agent — User Manual

## Digital Signature Certificate Agent with eSwakshar Integration

---

# Table of Contents

1. [Overview](#1-overview)
2. [System Requirements](#2-system-requirements)
3. [Installation](#3-installation)
4. [Configuration](#4-configuration)
5. [Running the Agent](#5-running-the-agent)
6. [HTTP API Reference](#6-http-api-reference)
7. [Browser SDK Usage](#7-browser-sdk-usage)
8. [Electron Tray Application](#8-electron-tray-application)
9. [Signing Workflow](#9-signing-workflow)
10. [eSwakshar Time Server Integration](#10-eswakshat-time-server-integration)
11. [Security](#11-security)
12. [Troubleshooting](#12-troubleshooting)
13. [FAQ](#13-faq)

---

# 1. Overview

## 1.1 What is DSC Agent?

**DSC Agent** is a local HTTP service that acts as a bridge between web applications and USB hardware cryptographic tokens (Digital Signature Certificates / DSCs). It allows any web application to digitally sign PDF documents using a USB DSC token via the PKCS#11 standard — without requiring browser plugins or native installers on the client machine beyond the agent itself.

## 1.2 What is eSwakshar?

**eSwakshar** (also spelled Swakshar / Swakshat) is the e-Signature authorization and trusted timestamp service integrated with this agent. It provides:

- **Signing authorization** — validates the signer's identity and authorizes each signing operation
- **Trusted timestamps** — provides a cryptographically verifiable signing time from a trusted time server
- **Audit trail** — records each signing transaction for compliance

The eSwakshar service endpoint is configured at `https://103.158.204.86/swakshar/` (Assam State Data Center).

## 1.3 How It Works

```
Web Browser (HTML/JS App)
        |
        | HTTP (fetch) to 127.0.0.1:18080
        v
+---------------------------+
|    DSC Agent (Node.js)    |
|  - Express HTTP Server    |
|  - PKCS#11 via pkcs11js   |
|  - PDF signing via        |
|    @signpdf/signpdf       |
|  - eSwakshar client for   |
|    authorization & time   |
+---------------------------+
        |
        | PKCS#11
        v
+---------------------------+
|   USB DSC Token (Hardware) |
|   - Private Key (RSA)     |
|   - Digital Certificate   |
+---------------------------+
```

## 1.4 Key Features

- **PDF Signing (PAdES)** — Sign PDFs with SHA256-RSA, compliant with PDF Advanced Electronic Signature standards
- **Batch Signing** — Sign multiple PDFs with a single PIN prompt
- **Re-sign with Flatten** — Strip existing signatures, preserve visual appearance, and re-sign
- **Text Signing** — Sign arbitrary text (returns base64-encoded signature)
- **Token Auto-Detection** — Automatically detects common PKCS#11 tokens (ProxKey, ePass2003, SafeNet eToken, OpenSC, Watchdata mToken)
- **Certificate Chain Embedding** — Fetches intermediate CA certificates via AIA (Authority Information Access)
- **LTV (Long-Term Validation)** — Optional OCSP/CRL revocation information embedding
- **eSwakshar Integration** — Remote signing authorization and trusted timestamping
- **Custom Signature Appearance** — Configurable position, size, anchor, and text
- **Browser SDK** — Lightweight JavaScript client for easy web integration
- **Electron Tray App** — Desktop system tray UI for managing the agent

---

# 2. System Requirements

## 2.1 Hardware

- Computer with a USB port
- USB DSC token (PKCS#11 compliant), e.g.:
  - ProxKey
  - ePass2003 / HYP 2003
  - SafeNet eToken
  - OpenSC-compatible token
  - Watchdata mToken

## 2.2 Software

| Component | Requirement |
|-----------|-------------|
| Operating System | Windows 7+ (x64), macOS 10.15+, Linux (x64) |
| Node.js | v18+ (for development) OR bundled portable runtime (for end users) |
| PKCS#11 Driver | Vendor-provided token middleware DLL/SO/DYLIB |
| RAM | Minimum 256 MB |
| Disk Space | Minimum 100 MB |

## 2.3 Supported PKCS#11 Modules

The agent auto-detects these common drivers:

| Token | Windows DLL | Linux SO | macOS DYLIB |
|-------|-------------|----------|-------------|
| ProxKey | `SignatureP11.dll` | `libSignatureP11.so` | `libSignatureP11.dylib` |
| ePass2003 | `eps2003csp11.dll` | `libeps2003csp11.so` | `libeps2003csp11.dylib` |
| HYP 2003 | `eps2003csp11v2.dll` | `libeps2003csp11v2.so` | `libeps2003csp11v2.dylib` |
| SafeNet eToken | `eTPKCS11.dll` | `libeTPkcs11.so` | `libeTPkcs11.dylib` |
| OpenSC | `opensc-pkcs11.dll` | `opensc-pkcs11.so` | `opensc-pkcs11.so` |
| Watchdata mToken | `wdpkcs.dll` | `libwdpkcs.so` | `libwdpkcs.dylib` |

---

# 3. Installation

## 3.1 Development Installation

```bash
# Clone the repository
git clone <repo-url>
cd dsc-agent

# Install dependencies
npm ci

# Install Electron app dependencies
cd electron-app
npm ci
cd ..
```

## 3.2 End-User Installation (Windows Installer)

1. Download the DSC Agent installer (`DSC Agent Setup-x.x.x.exe`)
2. Double-click the installer and follow the on-screen instructions
3. Launch "DSC Agent" from the Start Menu
4. The agent appears in the system tray

## 3.3 PKCS#11 Driver Installation

Before using the agent, install the middleware/driver for your USB token:

- **ProxKey**: Install ProxKey middleware from your token provider
- **ePass2003**: Install Feitian ePass2003 driver
- **SafeNet eToken**: Install SafeNet Authentication Client
- **OpenSC**: Install OpenSC from https://github.com/OpenSC/OpenSC/wiki
- **Watchdata mToken**: Install Watchdata driver

---

# 4. Configuration

## 4.1 Configuration File (`dsc-agent.config.json`)

```json
{
  "requirePinPerSign": true,
  "timeServerUrl": "https://103.158.204.86/swakshar/",
  "timeServerEndpoint": "/api/time",
  "timeServerMethod": "POST",
  "timeServerTimeField": "server_time",
  "timeServerAllowSelfSigned": true,
  "allowOrigins": "*",
  "port": 18080,
  "signRect": [250, 40, 600, 90],
  "maxBodyMb": 100,
  "ltv": false,
  "ltvStrict": false
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `requirePinPerSign` | boolean | `true` | Require PIN entry for each signing operation |
| `timeServerUrl` | string | — | eSwakshar time server base URL |
| `timeServerEndpoint` | string | `/api/time` | Time server authorization endpoint |
| `timeServerMethod` | string | `POST` | HTTP method for time server (GET or POST) |
| `timeServerTimeField` | string | `server_time` | JSON field name for signing time in response |
| `timeServerAllowSelfSigned` | boolean | `true` | Allow self-signed TLS certificates for time server |
| `allowOrigins` | string/array | `*` | CORS allowed origins (comma-separated) |
| `port` | number | `18080` | Agent HTTP server port |
| `signRect` | array | `[250,40,600,90]` | Default signature rectangle `[x1,y1,x2,y2]` |
| `maxBodyMb` | number | `100` | Maximum request body size in MB |
| `ltv` | boolean | `false` | Enable LTV (OCSP/CRL) revocation info embedding |
| `ltvStrict` | boolean | `false` | Enable ETSI revocation values format |
| `pin` | string | — | Default PIN (not recommended for production) |
| `authToken` | string | — | Shared auth token for API authentication |
| `pkcs11Dll` | string | — | Explicit PKCS#11 DLL path |

## 4.2 Environment Variables

| Variable | Description |
|----------|-------------|
| `PKCS11_DLL` | Path to PKCS#11 DLL |
| `DSC_PIN` | Default PIN (use only for testing) |
| `DSC_AGENT_PORT` | HTTP port (default: 18080) |
| `ALLOW_ORIGINS` | CORS allowlist (comma-separated) |
| `DSC_AUTH_TOKEN` | Shared API auth token |
| `DSC_REQUIRE_PIN_PER_SIGN` | Force PIN per sign (`1`/`0`) |
| `DSC_SIGN_RECT` | Default signature rect `"x1,y1,x2,y2"` |
| `DSC_MAX_BODY_MB` | Max body size in MB |
| `DSC_LTV` | Enable LTV (`1`/`0`) |
| `DSC_CONFIG_PATH` | Custom config file path |
| `TIMESERVER_API_KEY` | API key for eSwakshar time server (read from `env` file) |

## 4.3 Configuration Precedence

1. Environment variables (highest priority)
2. Command-line arguments
3. `dsc-agent.config.json`
4. Built-in defaults (lowest priority)

---

# 5. Running the Agent

## 5.1 Running via Node.js (Development)

```bash
# From the project root
npm start
# or
node agent/dsc-agent.js
```

Expected output:
```
[dsc-agent] v0.1.0 listening on http://127.0.0.1:18080
```

## 5.2 Running via Electron Tray App (Production)

1. Launch "DSC Agent" from the Start Menu
2. The agent icon appears in the system tray
3. Click the tray icon to:
   - Start/Stop the agent
   - Open the Control Panel
   - View logs
   - Configure settings

## 5.3 Health Check

Verify the agent is running:

```bash
curl http://127.0.0.1:18080/health
```

Response:
```json
{
  "ok": true,
  "version": "0.1.0",
  "dll": "C:/Windows/System32/eps2003csp11.dll",
  "slotPresent": true,
  "requirePinPerSign": true,
  "promptAvailable": true
}
```

---

# 6. HTTP API Reference

The agent runs on `http://127.0.0.1:18080` (localhost only).

## 6.1 GET /health

Check agent status and token presence.

**Response:**
```json
{
  "ok": true,
  "version": "0.1.0",
  "dll": "path/to/pkcs11.dll",
  "slotPresent": true,
  "requirePinPerSign": true,
  "promptAvailable": true
}
```

## 6.2 GET /certs

List certificate/key pairs on the token.

**Headers:** `x-dsc-auth: <token>` (if `authToken` configured)

**Response:**
```json
{
  "ok": true,
  "pairs": [
    {
      "ckaIdHex": "abcd1234...",
      "subjectCN": "John Doe",
      "label": "My Certificate"
    }
  ]
}
```

## 6.3 POST /sign/pdf

Sign a single PDF.

**Headers:** `Content-Type: application/json`, `x-dsc-auth: <token>` (optional)

**Request Body:**
```json
{
  "pdfBase64": "<base64-encoded PDF>",
  "reason": "Signed via DSC Agent",
  "includeESS": true,
  "embedIntermediates": false,
  "pin": "123456",
  "requirePin": true,
  "rememberSessionPin": true,
  "rect": [250, 40, 600, 90],
  "rectMode": "pdf",
  "anchor": "top-left",
  "page": "last",
  "stampAllPages": false,
  "signingTime": "2024-01-15 10:30:00",
  "x": 50,
  "y": 50
}
```

**Response:**
```json
{
  "ok": true,
  "signedPdfBase64": "<base64-encoded signed PDF>"
}
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `pdfBase64` | string | — | Base64-encoded PDF to sign |
| `reason` | string | `"Signed via DSC Agent"` | Signing reason displayed in the signature |
| `includeESS` | boolean | `true` | Embed ESSCertIDv2 signed attribute |
| `embedIntermediates` | boolean | `false` | Fetch and embed intermediate CA certificates |
| `pin` | string | — | Token PIN (omit to trigger PIN prompt) |
| `requirePin` | boolean | — | Force PIN prompt even if session PIN exists |
| `rememberSessionPin` | boolean | `false` | Cache PIN in memory for session |
| `rect` | array | config default | Signature rectangle `[x1,y1,x2,y2]` or `[left,top]` |
| `rectMode` | string | `"pdf"` | `"pdf"` (absolute coords) or `"top-left"` (relative) |
| `anchor` | string | `"top-left"` | Anchor position: `top-left`, `top-right`, `bottom-left`, `bottom-right` |
| `page` | string/number | `"last"` | Page to sign: `"last"` or 1-based page number |
| `stampAllPages` | boolean | `false` | Duplicate signature visual on all pages |
| `signingTime` | string | — | Custom signing time (`"YYYY-MM-DD HH:mm:ss"`) |
| `x` / `y` | number | — | Shortcut for `rect` with `rectMode: "top-left"` |
| `apiKey` | string | — | eSwakshar API key |

## 6.4 POST /sign/pdf-batch

Sign multiple PDFs with a single PIN prompt.

**Request Body:**
```json
{
  "pdfs": ["<base64-pdf-1>", "<base64-pdf-2>"],
  "reason": "Batch signing",
  "requirePin": true,
  "rememberSessionPin": true
}
```

**Response:**
```json
{
  "ok": true,
  "results": [
    { "ok": true, "signedPdfBase64": "<base64>" },
    { "ok": false, "message": "Error description" }
  ]
}
```

## 6.5 POST /sign/pdf-resign-flatten

Strip existing signatures, preserve their visual appearance, and re-sign the PDF.

**Request Body:** Same as `/sign/pdf` with additional parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `stampPrevious` | boolean | `false` | Preserve previous signature text in page content |
| `useViewerAppearance` | boolean | `false` | Let PDF viewer render appearances |

## 6.6 POST /sign/text

Sign arbitrary text (returns the raw signature).

**Request Body:**
```json
{
  "text": "Data to sign",
  "pin": "123456"
}
```

**Response:**
```json
{
  "ok": true,
  "signature": "<base64-encoded RSA signature>",
  "signingTime": "2024-01-15T10:30:00.000Z"
}
```

## 6.7 POST /token/details

Get detailed token and certificate information.

**Request Body:**
```json
{
  "pin": "123456",
  "requirePin": true
}
```

**Response:**
```json
{
  "ok": true,
  "serialNumber": "0123456789",
  "name": "John Doe",
  "validFrom": "Jan 1 00:00:00 2024 GMT",
  "validTo": "Dec 31 23:59:59 2025 GMT",
  "subject": "CN=John Doe, O=Organization, C=IN",
  "token": {
    "label": "My Token",
    "manufacturer": "Feitian",
    "model": "ePass2003",
    "serial": "0123456789"
  }
}
```

## 6.8 GET /tokens

List known token types and detect available DLLs.

**Headers:** `x-dsc-auth: <token>` (if configured)

## 6.9 POST /token/select

Select a specific token or DLL path.

**Request Body:**
```json
{ "tokenName": "ePass2003" }
// OR
{ "dll": "C:/path/to/pkcs11.dll" }
```

## 6.10 POST /token/clear

Clear any user token/DLL selection (resets to auto-detection).

## 6.11 POST /shutdown

Shut down the agent (only when `DSC_ALLOW_SHUTDOWN=1` and from localhost).

## 6.12 Error Codes

| HTTP Status | Meaning |
|-------------|---------|
| 400 | Bad request (missing fields, invalid parameters) |
| 401 | Invalid PIN |
| 423 | PIN locked |
| 500 | Internal server error |
| 502 | Time server / authorization error |
| 503 | Token not detected |

Error responses:
```json
{
  "ok": false,
  "message": "Human-readable error description"
}
```

---

# 7. Browser SDK Usage

## 7.1 Quick Start (ES Module)

```html
<script type="module">
  import { discover } from './client/dsc-agent-client.js';

  const agent = await discover();
  const health = await agent.health();
  console.log('Agent status:', health);
</script>
```

## 7.2 Sign a PDF

```html
<script type="module">
  import { discover, utils } from './client/dsc-agent-client.js';

  const agent = await discover();

  document.querySelector('#signBtn').onclick = async () => {
    const file = document.querySelector('#pdfFile').files[0];
    const ab = await utils.fileToArrayBuffer(file);

    const result = await agent.signPdf(ab, {
      reason: 'Signed via DSC Agent',
      includeESS: true,
      requirePin: true,
      rememberSessionPin: true
    });

    // Download the signed PDF
    const link = document.createElement('a');
    link.href = 'data:application/pdf;base64,' + result.signedPdfBase64;
    link.download = 'signed.pdf';
    link.click();
  };
</script>
```

## 7.3 Auto-Wire (No JavaScript Required)

For the simplest integration, just add HTML elements with default IDs:

```html
<input id="dsc-file" type="file" accept="application/pdf">
<button id="dsc-sign">Sign PDF</button>
<div id="dsc-status"></div>
<a id="dsc-download" style="display:none">Download Signed PDF</a>
<object id="dsc-viewer" type="application/pdf"
        style="width:100%;height:380px"></object>

<script src="./client/dsc-agent-client.iife.js"></script>
<script src="./client/dsc-agent-autowire.js"></script>
```

## 7.4 SDK API Reference

### `discover(port?, timeout?)`
Discover the DSC Agent on localhost. Returns an `agent` instance.

- `port`: Port number or array of ports (default: `[18080, 18081, 18082]`)
- `timeout`: Discovery timeout in ms (default: `500`)

### `agent.health()`
GET `/health`. Returns agent status object.

### `agent.certs()`
GET `/certs`. Returns certificate list.

### `agent.signPdf(pdfArrayBuffer, options)`
POST `/sign/pdf`. Signs a single PDF.

### `agent.signPdfBatch(files, options)`
POST `/sign/pdf-batch`. Signs multiple PDFs.

### `agent.signText(text, options)`
POST `/sign/text`. Signs arbitrary text.

---

# 8. Electron Tray Application

## 8.1 Overview

The Electron tray app provides a desktop interface for managing the DSC Agent:

- **System Tray Icon** — Quick access to agent controls
- **Start/Stop Agent** — Control the agent process
- **Control Panel** — View status, configure settings
- **Logs** — View real-time agent logs
- **PIN Prompt** — Secure PIN entry dialog

## 8.2 Control Panel

The control panel allows you to:

- View agent health status
- List certificates on the token
- Configure PKCS#11 DLL path
- Change port number
- Set CORS allowed origins
- Select token type
- View agent logs

## 8.3 PIN Prompt

When `requirePinPerSign` is enabled:

1. The web app requests a sign operation
2. The agent sends a prompt request to the Electron PIN prompt server
3. A modal dialog appears asking for the token PIN
4. The PIN is sent back to the agent securely (never logged)
5. The agent uses the PIN for the signing operation

---

# 9. Signing Workflow

## 9.1 Standard PDF Signing Flow

```
1. User inserts USB DSC token
         |
2. Web app discovers DSC Agent via SDK
         |
3. User selects PDF and clicks "Sign"
         |
4. Agent validates token presence
         |
5. Agent requests PIN (via Electron prompt or API body)
         |
6. Agent contacts eSwakshar time server:
   a. Sends signer identity + API key
   b. Receives authorization + trusted timestamp
         |
7. Agent detects signing key on token
         |
8. Agent builds PDF placeholder:
   a. Inserts signature field
   b. Configures appearance (rect, text, checkmark)
   c. Optionally stamps all pages
         |
9. Agent signs using PKCS#11:
   a. Creates CMS/PAdES signature
   b. Embeds certificate chain
   c. Adds signed attributes (ESS, signing time)
         |
10. Agent returns signed PDF (base64) to web app
         |
11. Web app offers download to user
```

## 9.2 Batch Signing Flow

Same as above, but:
- PIN is prompted once for the entire batch
- eSwakshar authorization is obtained per PDF
- PIN is reused across all PDFs in the batch (or cached in session)

## 9.3 Re-sign with Flatten Flow

1. Load PDF with existing signature(s)
2. Strip all AcroForm signature fields
3. Remove DocMDP permissions
4. Optionally preserve previous signature visuals in page content
5. Create fresh PDF without signatures
6. Sign as a new signature

---

# 10. eSwakshar Time Server Integration

## 10.1 Overview

The eSwakshar integration provides:

- **Signing Authorization** — Validates each signing request before the signature is created
- **Trusted Timestamp** — Returns a cryptographically verifiable signing time
- **Audit Trail** — Records transaction details for compliance

## 10.2 Configuration

Configure the time server in `dsc-agent.config.json`:

```json
{
  "timeServerUrl": "https://103.158.204.86/swakshar/",
  "timeServerEndpoint": "/api/time",
  "timeServerMethod": "POST",
  "timeServerTimeField": "server_time",
  "timeServerAllowSelfSigned": true
}
```

## 10.3 API Key

Set the API key in the `env` file:

```
TIMESERVER_API_KEY=6d801253672ab113218b1c799fe113e4dbcec8b7b9d5433d9398f48cb8633b76
```

Or send it per-request via:
- `x-api-key` HTTP header
- `apiKey` field in the request body

## 10.4 Authorization Payload

The agent sends the following payload to the time server:

```json
{
  "name": "John Doe",
  "machineHash": "<token-serial-or-machine-id>",
  "apiKey": "<your-api-key>",
  "osPlatform": "win32"
}
```

## 10.5 Expected Response

```json
{
  "server_time": "2024-01-15T10:30:00.000Z"
}
```

The `server_time` field name is configurable via `timeServerTimeField`.

## 10.6 Health Check on Boot

On startup, the agent performs a health check against the time server (unless a custom `timeServerUrl` is configured, in which case it's skipped).

---

# 11. Security

## 11.1 Network Security

- The agent binds **only** to `127.0.0.1` (localhost)
- External network access is not possible
- CORS is enforced for web origin restrictions

## 11.2 PIN Security

- PIN is **never logged** to console or files
- PIN is **never persisted** to disk
- Optional per-sign PIN prompt via Electron UI
- In-memory session PIN caching (process-lifetime only)
- PIN is sent over localhost HTTP (never leaves the machine)

## 11.3 Authentication

- Optional shared auth token (`DSC_AUTH_TOKEN`) for API access
- Sent via `x-dsc-auth` HTTP header
- When set, all API endpoints require this token

## 11.4 CORS

- Configurable allowlist via `ALLOW_ORIGINS` or `allowOrigins`
- In production, restrict to specific origins (e.g., your application domain)
- Default `*` allows all local origins (safe since agent is localhost-only)

## 11.5 PKCS#11 Driver

- Party drivers must be obtained from trusted sources (token vendor or OpenSC)
- The agent does not include or distribute PKCS#11 drivers

---

# 12. Troubleshooting

## 12.1 Common Issues

### "No PKCS#11 module found" / "DSC token not detected"

- **Cause**: PKCS#11 driver not installed or token not inserted
- **Solution**:
  1. Install the token middleware (vendor driver)
  2. Insert the USB token
  3. Check device manager that the token is recognized
  4. Verify the DLL path in config or specify via `PKCS11_DLL`

### "Invalid PIN"

- **Cause**: Wrong PIN entered
- **Solution**:
  1. Check with your token provider for the correct PIN
  2. Note: multiple failed attempts may lock the PIN

### "PIN locked"

- **Cause**: Too many incorrect PIN attempts
- **Solution**: Contact your token provider to unlock the PIN

### "CORS error" from browser

- **Cause**: Origin not allowed
- **Solution**: Set `ALLOW_ORIGINS` to include your web app's origin or `*`

### "Input PDF already contains a signature"

- **Cause**: Attempting to sign a file that already has a signature
- **Solution**: Use `/sign/pdf-resign-flatten` to strip and re-sign

### Time server authorization fails

- **Cause**: API key missing or incorrect
- **Solution**:
  1. Verify `TIMESERVER_API_KEY` in the `env` file
  2. Check network connectivity to the time server
  3. Verify `timeServerUrl` and `timeServerEndpoint` configuration

## 12.2 Logs

Enable detailed logging by running the agent in the console:

```bash
node agent/dsc-agent.js
```

All logs are printed to stdout/stderr.

## 12.3 Diagnostic Commands

```bash
# Health check
curl http://127.0.0.1:18080/health

# List certificates
curl http://127.0.0.1:18080/certs -H "x-dsc-auth: <token>"

# Token details
curl -X POST http://127.0.0.1:18080/token/details \
  -H "Content-Type: application/json" \
  -d '{"requirePin": true}'

# List detected tokens
curl http://127.0.0.1:18080/tokens
```

---

# 13. FAQ

**Q: Do I need Node.js installed to use DSC Agent?**
A: For end users, no. The Windows installer bundles a portable Node.js runtime. For development, Node.js v18+ is required.

**Q: Can I use DSC Agent without eSwakshar?**
A: Yes. The agent can be configured without a time server by leaving `timeServerUrl` empty. However, signing authorization and trusted timestamps will not be available.

**Q: What PDF standards are supported?**
A: PAdES (PDF Advanced Electronic Signature) with SHA256-RSA, compliant with PDF specification.

**Q: Can I sign PDFs on mobile devices?**
A: No. The DSC Agent runs on desktop operating systems (Windows, macOS, Linux) and requires a USB connection to the token.

**Q: How many PDFs can I sign in batch mode?**
A: There is no hard limit, but each PDF is processed sequentially to maintain token session stability.

**Q: Can I use multiple tokens on the same machine?**
A: Yes. Use `/token/select` to switch between tokens, or configure `PKCS11_DLL` to point to the desired driver.

**Q: Does the agent support ECDSA keys?**
A: Currently, only RSA keys are supported for signing.

**Q: How do I update the agent?**
A: Download the latest installer and re-run it, or pull the latest code from the repository.

---

# Appendix A: Error Reference

| Error Code | Message | Action |
|------------|---------|--------|
| `DSC_TOKEN_MISSING` | Token not detected | Insert USB token |
| `CKR_PIN_LOCKED` | PIN is locked | Contact token provider |
| `CKR_PIN_INCORRECT` | Invalid PIN | Re-enter correct PIN |
| `CKR_PIN_LEN_RANGE` | PIN length invalid | Check PIN format |
| `CKR_TOKEN_NOT_PRESENT` | Token removed | Reconnect token |
| `CKR_DEVICE_REMOVED` | Token removed during operation | Reconnect and retry |

# Appendix B: File Structure

```
dsc-agent/
├── agent/
│   ├── dsc-agent.js                  # Main agent entry point
│   ├── timeServerClient.js           # eSwakshar HTTP client
│   ├── lib/
│   │   ├── config.js                 # Configuration loader
│   │   ├── pkcs11.js                 # PKCS#11 operations
│   │   ├── pdf.js                    # PDF utilities
│   │   ├── pinPromptClient.js        # PIN prompt HTTP client
│   │   └── signAuthorizationPayloadBuilder.js
│   └── services/
│       ├── signingTimeService.js     # Time server authorization
│       └── timeServerHealthService.js
├── client/
│   ├── dsc-agent-client.js           # ES module SDK
│   ├── dsc-agent-client.iife.js      # Browser script SDK
│   ├── dsc-agent-client.d.ts         # TypeScript types
│   ├── dsc-agent-autowire.js         # Auto-wiring helper
│   ├── dsc-agent-config.js           # Config helper
│   └── time-provider.js              # Time utility
├── electron-app/
│   ├── main.js                       # Electron main process
│   ├── preload.js                    # Context bridge
│   ├── main/pinPromptServer.js       # PIN prompt HTTP server
│   └── renderer/                     # Control Panel UI
├── working/                          # HTML test/demo pages
├── dsc-agent.config.json             # Configuration file
├── env                               # API keys (gitignored)
└── package.json
```

# Appendix C: Quick Reference Card

```
START AGENT:     npm start  OR  node agent/dsc-agent.js
HEALTH CHECK:    curl http://127.0.0.1:18080/health
LIST CERTS:      curl http://127.0.0.1:18080/certs
SIGN PDF:        POST /sign/pdf   { pdfBase64, ... }
BATCH SIGN:      POST /sign/pdf-batch  { pdfs: [...], ... }
RE-SIGN:         POST /sign/pdf-resign-flatten  { pdfBase64, ... }
SIGN TEXT:       POST /sign/text  { text, ... }
TOKEN DETAILS:   POST /token/details
DEFAULT PORT:    18080
BIND ADDRESS:    127.0.0.1 (localhost only)
```

---

*DSC Agent v1.0.0 — Built for eSwakshar e-Signature Platform*
*Assam State Data Center / RTPS Platform*
