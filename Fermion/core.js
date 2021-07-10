const { app, BrowserWindow } = require('electron');
app.commandLine.appendSwitch('disable-features', 'CrossOriginOpenerPolicy');

let bWin

function createWindow() {
  // Create the browser window.
  bWin = new BrowserWindow({
    contextIsolation: false,
    width: 1000,
    height: 900,
    frame: false,
    show: false,
    backgroundColor: '#464646',
    webPreferences: {
      nodeIntegration: true,
      enableRemoteModule: true,
      contextIsolation: false
    }
  })

  // and load the index.html of the app.
  bWin.loadURL(`file://${__dirname}/src/frida.html`);

  // show the window only when the web page has been rendered
  bWin.once('ready-to-show', () => {
    // We still need a minor delay
    setTimeout(function () {
      bWin.show();
      bWin.focus();
    }, 500);
  });

  // Emitted when the window is closed.
  bWin.on('closed', () => {
    // Dereference the window object, usually you would store windows
    // in an array if your app supports multi windows, this is the time
    // when you should delete the corresponding element.
    bWin = null
  })
}

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.on('ready', createWindow)

// Quit when all windows are closed.
app.on('window-all-closed', () => {
  app.quit()
})

app.on('activate', () => {
  // On macOS it's common to re-create a window in the app when the
  // dock icon is clicked and there are no other windows open.
  if (bWin === null) {
    createWindow()
  }
})

// Add listener for device selector
const ipc = require('electron').ipcMain;
ipc.on('device-selector', (event, message) => bWin.webContents.send('device-selector', message));