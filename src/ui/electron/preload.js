const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('starAPI', {
    onEvent: (callback) => ipcRenderer.on('star-event', callback),
    requestStatus: () => ipcRenderer.send('request-status')
});
