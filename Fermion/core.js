const { app, BrowserWindow } = require('electron')

let bWin

function createWindow() {
  // Create the browser window.
  bWin = new BrowserWindow({
    width: 1000,
    height: 850,
    frame: false,
    show: false,
    backgroundColor: '#464646',
    webPreferences: {
      nodeIntegration: true
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

// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and require them here.