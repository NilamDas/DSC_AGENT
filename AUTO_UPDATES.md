# DSC Agent automatic updates

DSC Agent checks for updates 30 seconds after startup and every six hours after
that. Users can also choose **Check for Updates** from the tray menu or the Help
menu. The application asks before downloading an update and asks again before
restarting to install it.

Update checks run only in packaged builds. Development runs do not contact an
update server.

## Configure the update server

The Windows protected build reads the update-feed URL from `DSC_UPDATE_FEED_URL`
or, when that environment variable is absent, from `updateFeedUrl` in
`dsc-agent.config.json`. This URL is embedded in the installed application as
its update feed. The build fails when neither value is configured, preventing
creation of an installer that cannot update itself.

Windows PowerShell example:

```powershell
$env:DSC_UPDATE_FEED_URL = 'https://updates.example.com/dsc-agent/stable/'
powershell -NoProfile -ExecutionPolicy Bypass -File .\build-protected.ps1
```

Linux or macOS example:

```bash
DSC_UPDATE_FEED_URL='https://updates.example.com/dsc-agent/stable/' bash build-linux.sh
# or: bash build-mac.sh
```

If the variable is omitted, the installer still builds, but that build has no
configured update feed and automatic checks cannot find releases.

The update directory must be publicly readable over HTTPS and support byte-range
requests. A generic static web server, object-storage bucket, or CDN is suitable.

## Publish a release

1. Increase the application version in `package.json`,
   `electron-app/package.json`, and `electron-app/package.json-bytecode-point`.
   Update `electron-app/package-lock.json` to match.
2. Build with the same stable `DSC_UPDATE_FEED_URL` used for previous releases.
3. Upload the generated installer, update manifest, and blockmap files from
   `electron-app/dist/` to that URL. Keep the generated filenames unchanged.

Typical files are:

- Windows: `latest.yml`, the NSIS setup `.exe`, and its `.blockmap`.
- macOS: `latest-mac.yml`, `.dmg`, `.zip`, and blockmap files.
- Linux: `latest-linux.yml`, `.AppImage`, and related package files.

The version must always increase. Reusing a version number will not update
clients that already installed that version.

## Signing requirements

- macOS auto-update requires a Developer ID-signed application. The DMG and ZIP
  targets are both enabled because the ZIP artifact is required by the macOS
  updater. Set `CSC_IDENTITY_AUTO_DISCOVERY=true` and provide the normal Electron
  Builder signing credentials when producing a macOS release.
- Windows releases should be signed consistently with the same code-signing
  identity. Installed clients validate the publisher before applying updates.
- Test updates using an installed build. Electron's updater is intentionally
  disabled in development mode.

Do not delete an update manifest while clients may still be polling it. Publish
the installer and blockmap first, then publish the manifest last so clients never
see an incomplete release.
