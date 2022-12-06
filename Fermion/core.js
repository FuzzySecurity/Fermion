// Modules to control application life and create native browser window
const {app, BrowserWindow} = require('electron');
const path = require('path');
const ipcMain = require('electron').ipcMain;
var bWin;
app.commandLine.appendSwitch('disable-features', 'CrossOriginOpenerPolicy');
require('@electron/remote/main').initialize();

function createWindow() {
  // Create the browser window.
  bWin = new BrowserWindow({
    contextIsolation: false,
    width: 1024,
    minWidth: 1024,
    maxWidth: 3000,
    height: 930,
    minHeight: 930,
    frame: false,
    show: false,
    transparent: false,
    webPreferences: {
      nodeIntegration: true,
      nodeIntegrationInWorker: true,
      enableRemoteModule: true,
      contextIsolation: false,
      webviewTag: true
    }
  });
  
  // needed after electron v14.0.1
  // https://stackoverflow.com/questions/69059668/enableremotemodule-is-missing-from-electron-v14-typescript-type-definitions/69059669#69059669
  require('@electron/remote/main').enable(bWin.webContents);

  // and load the index.html of the app.
  bWin.loadFile(path.join(__dirname, '/pages/index.html'));

  // show the window only when the web page has been rendered
  bWin.once('ready-to-show', () => {
    // We still need a minor delay
    setTimeout(function () {
      bWin.show();
      bWin.focus();
    }, 500);
  });
}

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.whenReady().then(() => {
  createWindow()

  app.on('activate', function () {
    // On macOS it's common to re-create a window in the app when the
    // dock icon is clicked and there are no other windows open.
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit()
})

// IPC listeners
ipcMain.on('new-device', (event, message) => bWin.webContents.send('new-device', message));
ipcMain.on('attach-process', (event, message) => bWin.webContents.send('attach-process', message));
ipcMain.on('attach-process-shim', (event, message) => bWin.webContents.send('attach-process-shim', message));
ipcMain.on('start-process-shim', (event, message) => bWin.webContents.send('start-process-shim', message));
ipcMain.on('trace-data-recv', (event, message) => bWin.webContents.send('trace-data-recv', message));