const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('DSC', {
  getSettings: () => ipcRenderer.invoke('settings:get'),
  setSettings: (s) => ipcRenderer.invoke('settings:set', s),
  startAgent: () => ipcRenderer.invoke('agent:start'),
  stopAgent: () => ipcRenderer.invoke('agent:stop'),
  getLogs: () => ipcRenderer.invoke('logs:get'),
  browseDll: () => ipcRenderer.invoke('dll:browse'),
  getDllPresets: () => ipcRenderer.invoke('dll:presets'),
  downloadInstallationGuide: () => ipcRenderer.invoke('document:download-installation-guide'),
  notify: (title, body) => ipcRenderer.invoke('notify', title, body),
});
