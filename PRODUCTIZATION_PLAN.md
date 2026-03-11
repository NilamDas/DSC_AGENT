DSC Agent Productization Plan

Goal: Ship a simple Windows installer that bundles the tray UI and the DSC agent so a client can install and start signing PDFs with their USB token without installing Node.js manually.

Principles
- Keep the working dsc-agent.js intact; do not modify signing logic.
- Electron is UI-only. It should never require or load pkcs11js.
- External apps communicate over the agent's localhost HTTP API.

Architecture
- Agent: dsc-agent.js (Node), binds 127.0.0.1, exposes /health, /certs, /sign/pdf, /sign/pdf-batch.
- Electron app: tray app that starts/stops the agent as a child process, shows status and settings.
- Web apps/native apps: call the HTTP API directly (or via browser_sdk.js).

Current State
- electron-app/: Isolated Electron project (dev/build) that does not touch the agent code.
- Control Panel: Start/Stop agent, view logs, edit settings (PKCS11_DLL, port, CORS, token, etc.), basic health/certs calls.

Configured Packaging
- electron-builder packaging (NSIS and portable on Windows) with extraResources to include the agent code+deps.
- extraResources also bundles a local Node runtime if placed under electron-app/bin/** (copied to resources/bin/** at build time).
- Root script `npm run build:win` to build the installer from repo root.

Prepare the Node runtime (one-time)
- Download a portable Node.js for Windows (x64) matching your architecture (ZIP distribution).
- Copy node.exe to: electron-app/bin/win/node.exe
- Only node.exe is required to run the agent.

Build steps
1) Install deps (dev machine):
   - In repo root: npm ci
   - In electron-app: npm ci
2) Verify agent locally: npm run dev (root), then curl http://127.0.0.1:18080/health
3) Build the installer: npm run build:win (from repo root)
   - Output: electron-app/dist/ (NSIS .exe, portable .exe)

Client install and usage
- Run the NSIS installer on the client machine.
- Launch “DSC Agent” from Start Menu; it appears in the system tray.
- Tray menu: Start/Stop the agent, open Control Panel, view logs.
- Your app calls http://127.0.0.1:18080.

HTTP API (summary)
- GET `/health`: status + config flags
- GET `/certs`: list token key/cert pairs
- POST `/sign/pdf`: sign a single PDF
  - Body: `{ pdfBase64, reason?, includeESS?, embedIntermediates?, signingTime?, pin?, requirePin?, rememberSessionPin?, rect?, anchor?, page? }`
  - Result: `{ ok, signedPdfBase64 }`
- POST `/sign/pdf-batch`: sign multiple PDFs without breaking single-PDF flow
  - Body: `{ pdfs: string[], reason?, includeESS?, embedIntermediates?, signingTime?, pin?, requirePin?, rememberSessionPin?, rect?, anchor?, page? }`
  - Result: `{ ok, results: [ { ok, signedPdfBase64 } | { ok:false, message } ] }`
  - PIN prompt is issued once for the whole batch when required and reused for all items (unless a session PIN is already set).

Configuration
- In tray UI settings:
  - PKCS11_DLL: path to token driver (DLL)
  - ALLOW_ORIGINS: CORS allowlist
  - DSC_AGENT_PORT: default 18080
  - DSC_PIN: optional default PIN
  - DSC_AUTH_TOKEN: optional shared token

Security notes
- Agent binds to 127.0.0.1 only.
- Keep ALLOW_ORIGINS restrictive in production.
- When a client requests per-sign PIN via the API, the agent prompts through the local Electron UI using a localhost callback protected with a per-run random bearer token; the PIN is never logged or persisted.

Driver prerequisites
- Client must install vendor token middleware (PKCS#11 DLL) or OpenSC.

Optional later
- Auto-launch on login; code-sign installer; service-mode option.
Time Server
- we can use https://worldtimeapi.org/api/timezone/Asia/Kolkata