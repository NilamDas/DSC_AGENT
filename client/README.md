DSC Agent Browser SDK

Overview
- Lightweight helper for discovering and calling the local DSC Agent over HTTP from any web application.
- No dependency on pkcs11js; pure HTTP to `http://127.0.0.1:<port>`.

Files
- `client/dsc-agent-client.js`: ES module export (preferred for modern apps).
- `client/dsc-agent-client.d.ts`: TypeScript declarations.
- `client/dsc-agent-client.iife.js`: Non-module build for `<script>` usage.
- `client/dsc-agent-autowire.js`: Super-simple auto-wiring helper for basic pages.

Quick Start (ES Module)
1) Include the module in your page or bundler entry:

   <script type="module">
     import { discover } from './client/dsc-agent-client.js';
     const agent = await discover();
     console.log(await agent.health());
   </script>

2) Sign a PDF selected via `<input type="file">`:

   import { discover, utils } from './client/dsc-agent-client.js';
   const agent = await discover();
   const file = document.querySelector('#pdf').files[0];
   const ab = await utils.fileToArrayBuffer(file);
   const { signedPdfBase64 } = await agent.signPdf(ab, {
     reason: 'Signed via DSC Agent',
     includeESS: true,
     embedIntermediates: false,
   });

3) Batch sign with fallback (uses `/sign/pdf-batch` if available, else loops client‑side):

   const files = Array.from(document.querySelector('#pdf').files);
   const res = await agent.signPdfBatch(files, {
     reason: 'Batch',
     requirePin: true,
     rememberSessionPin: true,
     // Optional PIN callback when the agent cannot prompt:
     pinPrompt: async () => window.prompt('Enter token PIN for this batch:', '') || '',
   });
   console.log(res.results);

Notes
- Discovery scans ports `[18080, 18081, 18082]` with a short timeout; override if needed.
- Your web app’s origin must be allowed by the agent’s `ALLOW_ORIGINS` setting.
- The agent binds to `127.0.0.1` only; calls never leave the machine.
- If the agent supports prompting (see `health().promptAvailable`), prefer `requirePin`/`rememberSessionPin` over sending `pin` directly.

Simplest HTML (no custom JS)
- Add minimal markup with default IDs and include two scripts (works from `file://` if CORS allows `null` origin):

  <input id="dsc-file" type="file" accept="application/pdf">
  <button id="dsc-sign">Sign PDF</button>
  <div id="dsc-status"></div>
  <a id="dsc-download" style="display:none">Download</a>
  <object id="dsc-viewer" type="application/pdf" style="width:100%;height:380px"></object>

  <script src="./client/dsc-agent-client.iife.js"></script>
  <script src="./client/dsc-agent-autowire.js"></script>

That’s all. The autowire script discovers the agent, enables the button, signs on click, updates status, and prepares a download link (and inline preview if present).

Custom selectors (one-liner)
- If you don’t want to use the default IDs, call:

  <script>
    window.DSCAuto.wire({
      file: '#myFile',
      button: '#mySign',
      status: '#myStatus',
      download: '#myDownload',
      viewer: '#myViewer',
      reason: 'My Business Reason',
      // Optional toggles if present: ess: '#myEss', interm: '#myInterm', stampAll: '#myStampAll', remember: '#myRemember',
      // Optional signing time input: signingTimeSel: '#mySigningTime'
    });
  </script>

Local file vs HTTP
- For `file://` pages, the browser origin is `null`. Either allow `null` in `ALLOW_ORIGINS` or serve the page over HTTP (e.g., `http://127.0.0.1:8080`) and allow that origin.
