'use strict';

const DEFAULT_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;
const STARTUP_CHECK_DELAY_MS = 30 * 1000;

function createAutoUpdateController(options) {
  const {
    app,
    dialog,
    log = () => {},
    getMainWindow = () => null,
    onStateChange = () => {},
    checkIntervalMs = DEFAULT_CHECK_INTERVAL_MS,
  } = options || {};

  let autoUpdater = null;
  let startupTimer = null;
  let intervalTimer = null;
  let checkInProgress = false;
  let manualCheck = false;
  let promptInProgress = false;
  let downloadedUpdate = null;
  let state = 'idle';

  function setState(nextState) {
    state = nextState;
    try { onStateChange(nextState); } catch {}
  }

  function parentWindow() {
    const window = getMainWindow();
    return window && !window.isDestroyed() ? window : undefined;
  }

  function showMessageBox(config) {
    const window = parentWindow();
    return window ? dialog.showMessageBox(window, config) : dialog.showMessageBox(config);
  }

  async function promptToInstall(info) {
    if (promptInProgress) return;
    promptInProgress = true;
    try {
      const version = info && info.version ? ` ${info.version}` : '';
      const result = await showMessageBox({
        type: 'info',
        title: 'DSC Agent Update Ready',
        message: `DSC Agent${version} is ready to install.`,
        detail: 'Install now to restart the application and complete the update, or choose Later to continue working.',
        buttons: ['Install and Restart', 'Later'],
        defaultId: 0,
        cancelId: 1,
        noLink: true,
      });
      if (result.response === 0) {
        log(`[updater] Installing version ${info && info.version ? info.version : 'unknown'}`);
        setImmediate(() => autoUpdater.quitAndInstall(false, true));
      }
    } finally {
      promptInProgress = false;
    }
  }

  async function promptToDownload(info) {
    if (promptInProgress) return;
    promptInProgress = true;
    let shouldDownload = false;
    try {
      const version = info && info.version ? info.version : 'a newer version';
      const result = await showMessageBox({
        type: 'info',
        title: 'DSC Agent Update Available',
        message: `DSC Agent ${version} is available.`,
        detail: `You are currently using version ${app.getVersion()}. Download the update now?`,
        buttons: ['Download Update', 'Later'],
        defaultId: 0,
        cancelId: 1,
        noLink: true,
      });
      shouldDownload = result.response === 0;
    } finally {
      // Release the dialog lock before the download starts. The updater can
      // emit update-downloaded before downloadUpdate() resolves, and that event
      // must be able to open the install/restart prompt.
      promptInProgress = false;
    }

    if (!shouldDownload) {
      setState('available');
      return;
    }

    try {
      setState('downloading');
      await autoUpdater.downloadUpdate();
    } catch (error) {
      setState('error');
      log(`[updater] Download failed: ${error && error.message ? error.message : String(error)}`);
      await showMessageBox({
        type: 'error',
        title: 'Update Download Failed',
        message: 'DSC Agent could not download the update.',
        detail: error && error.message ? error.message : String(error),
      });
    }
  }

  function configureUpdater() {
    if (autoUpdater) return true;
    try {
      ({ autoUpdater } = require('electron-updater'));
    } catch (error) {
      log(`[updater] electron-updater is unavailable: ${error && error.message ? error.message : String(error)}`);
      setState('disabled');
      return false;
    }

    autoUpdater.autoDownload = false;
    autoUpdater.autoInstallOnAppQuit = false;
    autoUpdater.logger = {
      info: message => log(`[updater] ${String(message)}`),
      warn: message => log(`[updater] WARN: ${String(message)}`),
      error: message => log(`[updater] ERROR: ${String(message)}`),
      debug: message => log(`[updater] DEBUG: ${String(message)}`),
    };

    autoUpdater.on('checking-for-update', () => setState('checking'));
    autoUpdater.on('update-available', info => {
      checkInProgress = false;
      manualCheck = false;
      setState('available');
      log(`[updater] Version ${info.version} is available`);
      void promptToDownload(info);
    });
    autoUpdater.on('update-not-available', info => {
      const wasManual = manualCheck;
      checkInProgress = false;
      manualCheck = false;
      setState('idle');
      log(`[updater] Version ${info && info.version ? info.version : app.getVersion()} is current`);
      if (wasManual) {
        void showMessageBox({
          type: 'info',
          title: 'No Updates Available',
          message: 'You are using the latest version of DSC Agent.',
          detail: `Installed version: ${app.getVersion()}`,
        });
      }
    });
    autoUpdater.on('download-progress', progress => {
      setState('downloading');
      const percent = Number.isFinite(progress.percent) ? progress.percent.toFixed(1) : '0.0';
      log(`[updater] Downloaded ${percent}%`);
    });
    autoUpdater.on('update-downloaded', info => {
      checkInProgress = false;
      manualCheck = false;
      downloadedUpdate = info;
      setState('downloaded');
      log(`[updater] Version ${info.version} downloaded`);
      void promptToInstall(info);
    });
    autoUpdater.on('error', error => {
      const wasManual = manualCheck;
      checkInProgress = false;
      manualCheck = false;
      setState('error');
      log(`[updater] Check failed: ${error && error.message ? error.message : String(error)}`);
      if (wasManual) {
        void showMessageBox({
          type: 'error',
          title: 'Update Check Failed',
          message: 'DSC Agent could not check for updates.',
          detail: 'Verify the internet connection and update-feed configuration, then try again.\n\n' +
            (error && error.message ? error.message : String(error)),
        });
      }
    });
    return true;
  }

  async function checkForUpdates({ manual = false } = {}) {
    if (!app.isPackaged) {
      log('[updater] Skipping update check because the app is not packaged');
      if (manual) {
        await showMessageBox({
          type: 'info',
          title: 'Updates Disabled in Development',
          message: 'Automatic updates are checked only by an installed DSC Agent build.',
          detail: `Development version: ${app.getVersion()}`,
        });
      }
      return { skipped: true };
    }

    if (downloadedUpdate) {
      if (manual) await promptToInstall(downloadedUpdate);
      return { downloaded: true };
    }
    if (checkInProgress) return { busy: true };
    if (!configureUpdater()) return { disabled: true };

    checkInProgress = true;
    manualCheck = manual;
    setState('checking');
    try {
      return await autoUpdater.checkForUpdates();
    } catch (error) {
      // electron-updater normally emits "error" as well. Handle a rejected
      // check here in case a provider fails before the event is emitted.
      if (checkInProgress) {
        checkInProgress = false;
        manualCheck = false;
        setState('error');
        log(`[updater] Check rejected: ${error && error.message ? error.message : String(error)}`);
        if (manual) {
          await showMessageBox({
            type: 'error',
            title: 'Update Check Failed',
            message: 'DSC Agent could not check for updates.',
            detail: error && error.message ? error.message : String(error),
          });
        }
      }
      return { error };
    }
  }

  function start() {
    if (!app.isPackaged) {
      log('[updater] Periodic checks are disabled in development mode');
      return;
    }
    if (!configureUpdater()) return;
    startupTimer = setTimeout(() => void checkForUpdates(), STARTUP_CHECK_DELAY_MS);
    intervalTimer = setInterval(() => void checkForUpdates(), checkIntervalMs);
    if (typeof intervalTimer.unref === 'function') intervalTimer.unref();
    log(`[updater] Scheduled checks every ${Math.round(checkIntervalMs / 60000)} minutes`);
  }

  function stop() {
    if (startupTimer) clearTimeout(startupTimer);
    if (intervalTimer) clearInterval(intervalTimer);
    startupTimer = null;
    intervalTimer = null;
  }

  function getMenuLabel() {
    if (state === 'checking') return 'Checking for Updates…';
    if (state === 'downloading') return 'Downloading Update…';
    if (state === 'downloaded') return 'Install Downloaded Update…';
    return 'Check for Updates…';
  }

  return { start, stop, checkForUpdates, getMenuLabel };
}

module.exports = {
  createAutoUpdateController,
  DEFAULT_CHECK_INTERVAL_MS,
};
