const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('browserAPI', {
  navigate: (url) => ipcRenderer.send('navigate', url),
  goBack: () => ipcRenderer.send('go-back'),
  goForward: () => ipcRenderer.send('go-forward'),
  reload: () => ipcRenderer.send('reload'),
  toggleInspect: () => ipcRenderer.send('toggle-inspect'),
  loadExtension: (extRef) => ipcRenderer.send('load-extension', extRef),
  downloadVideo: (url) => ipcRenderer.send('download-video', url),
  scanMedia: () => ipcRenderer.send('scan-media'),
  setMediaFilter: (filter) => ipcRenderer.send('set-media-filter', filter),
  startDomainScan: (options) => ipcRenderer.send('start-domain-scan', options),
  stopDomainScan: () => ipcRenderer.send('stop-domain-scan'),
  clearMedia: () => ipcRenderer.send('clear-media'),
  toggleModal: (visibility) => ipcRenderer.send('toggle-modal', visibility),

  // Tab operations
  createTab: () => ipcRenderer.send('create-tab'),
  switchTab: (id) => ipcRenderer.send('switch-tab', id),
  closeTab: (id) => ipcRenderer.send('close-tab', id),
  
  // Events sent FROM main TO renderer
  onUrlChanged: (callback) => {
    ipcRenderer.removeAllListeners('url-changed');
    ipcRenderer.on('url-changed', (event, url) => callback(url));
  },
  onNavigationStateChange: (callback) => {
    ipcRenderer.removeAllListeners('nav-state-changed');
    ipcRenderer.on('nav-state-changed', (event, state) => callback(state));
  },
  onTabsUpdated: (callback) => {
    ipcRenderer.removeAllListeners('tabs-updated');
    ipcRenderer.on('tabs-updated', (event, tabs) => callback(tabs));
  },
  onDomainScanStatus: (callback) => {
    ipcRenderer.removeAllListeners('domain-scan-status');
    ipcRenderer.on('domain-scan-status', (event, status) => callback(status));
  }
});
