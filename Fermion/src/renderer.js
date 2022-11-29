const electron = require('electron');
const path = require('path');
const ipc = require('electron').ipcRenderer;
var MutexPromise = require('mutex-promise');
const remote = require('@electron/remote');
const BrowserWindow = remote.BrowserWindow;
const dialog = remote.dialog;
var fs = require('fs');
const frida = require('frida');
const { wrapExtraArgs } = require('../src/helper.js');

// Overwrite default node.js prop to get Jquery working
window.$ = window.jQuery = require('jquery');

// Globals
//////////////////////////////////////////////////

var MonacoCodeEditor;
var currentFilePath = null;
let script = null;
var session = null;
var sessionPID = null;
let logMutex = new MutexPromise('48011b2b9a930ee19e26320e5adbffa2e309663c');
let RunningLog = [];
var deviceId = 'local';

// Instrument
//////////////////////////////////////////////////

// -= Inject =-
async function inject(AttachTo) {
	// Exit on process termination
	process.on('SIGTERM', stop);
	process.on('SIGINT', stop);

	// Attach and load script
	device = await frida.getDevice(deviceId);
	session = await device.attach(AttachTo);
	sessionPID = session.pid.toString();
	traceSender.postMessage(sessionPID);
	session.detached.connect(onDetached);
	script = await session.createScript(MonacoCodeEditor.getValue());

	// For performance we can't update the text area all the time
	// it will lock the UI on big volumes of data. Instead we append
	// to an array using a mutex and every X ms we flush the array
	// to the text area
	script.message.connect(message => {
		if (message.type == "send") {
			ChangeLogExclusive(logMutex, 'Append', message.payload);
		} else {
			ChangeLogExclusive(logMutex, 'Append', "[!] Runtime error: " + message.stack);
		}
		setTimeout(function () {
			if (RunningLog.length > 0) {
				ChangeLogExclusive(logMutex, 'Write', null);
			}
		}, 500);
	});
	await script.load();
}

// -= Start =-
async function start(Path, Args) {
	// Exit on process termination
	process.on('SIGTERM', stop);
	process.on('SIGINT', stop);

	// Attach and load script
	device = await frida.getDevice(deviceId);
	if (!Args || 0 === Args.length) {
		procID = await device.spawn(Path);
	} else {
		var aBuildArgs = Args.split(" ");
		aBuildArgs.unshift(Path)
		procID = await device.spawn(aBuildArgs);
	}
	session = await device.attach(procID);
	sessionPID = session.pid.toString();
	traceSender.postMessage(sessionPID);
	session.detached.connect(onDetached);
	script = await session.createScript(MonacoCodeEditor.getValue());

	// For performance we can't update the text area all the time
	// it will lock the UI on big volumes of data. Instead we append
	// to an array using a mutex and every X ms we flush the array
	// to the text area
	script.message.connect(message => {
		if (message.type == "send") {
			ChangeLogExclusive(logMutex, 'Append', message.payload);
		} else {
			ChangeLogExclusive(logMutex, 'Append', "[!] Runtime error: " + message.stack);
		}
		setTimeout(function () {
			if (RunningLog.length > 0) {
				ChangeLogExclusive(logMutex, 'Write', null);
			}
		}, 500);
	});

	appendFridaLog('[+] Injecting => PID: ' + procID + ', Name: ' + Path);
	await script.load();

	device.resume(procID);
	appendFridaLog('[+] Process start success');
}

// -= On Terminate =-
function stop() {
	script.unload();
}

function onDetached(reason) {
	if (session != null) {
		session = null;
		traceSender.postMessage(null);
	}
	appendFridaLog(`[+] Exit Reason: ${reason}`);
}

// -= Detach =-

document.getElementById("FridaDetach").onclick = function () {
	if (session != null) {
		appendFridaLog('[+] Detaching..');
		session.detach();
		session = null;
		traceSender.postMessage(null);
	} else {
		appendFridaLog('[!] Not currently attached..');
	}
}

// -= Reload Script =-

document.getElementById("FridaReload").onclick = async function () {
	if (session != null) {
		if (script != null) {
			script.unload();
			script = await session.createScript(MonacoCodeEditor.getValue());
			script.message.connect(message => {
				if (message.type == "send") {
					ChangeLogExclusive(logMutex, 'Append', message.payload);
				} else {
					ChangeLogExclusive(logMutex, 'Append', "[!] Runtime error: " + message.stack);
				}
				setTimeout(function () {
					if (RunningLog.length > 0) {
						ChangeLogExclusive(logMutex, 'Write', null);
					}
				}, 500);
			});
			appendFridaLog('[+] Script reloaded..');
			await script.load();
		} else {
			appendFridaLog('[!] Not currently attached..');
		}
	} else {
		appendFridaLog('[!] Not currently attached..');
	}
}

// -= Proc Listing =-
async function getProcList() {
	let currentDevice = await frida.getDevice(deviceId);
	let Applications = await currentDevice.enumerateProcesses();
	return Applications;
}

// -= Shim for process list attach =-

ipc.on('attach-process', async (event, message) => {
	if (session == null) {
		appendFridaLog('[?] Attempting process attach..');
		getProcList().then(data => {
			// Search active processes
			var resultArray = [];
			data.find(function (element) {
				var Result = [];
				if (element.pid == message) {
					resultArray.push(element);
				}
			})

			// Do we have a single match?
			if (resultArray.length == 0) {
				appendFridaLog('[!] Process not found..');
				return;
			} else if (resultArray.length > 1) {
				appendFridaLog('[!] Ambiguous process match..');
				for (var i = 0; i < resultArray.length; i++) {
					appendFridaLog('PID: ' + resultArray[i].pid + ', Name: ' + resultArray[i].name);
				}
				return;
			} else {
				appendFridaLog('[+] Injecting => PID: ' + resultArray[0].pid + ', Name: ' + resultArray[0].name);
				inject(resultArray[0].pid).catch(e => {
					appendFridaLog(e);
				});
			}
		}).catch((err) => {
			appendFridaLog(`[!] Error: ${err.message}`);
		});

	} else {
		appendFridaLog('[!] Already attached to a process..');
	}
});

// -= Shim for attach invocation =-

ipc.on('attach-process-shim', async (event, message) => {
	if (session == null) {
		appendFridaLog('[?] Attempting process attach..');
		getProcList().then(data => {
			// What are we searching for?
			var ProcName = message[0];
			var ProcId = message[1];
			if ((!ProcId || 0 === ProcId.length) && (!ProcName || 0 === ProcName.length)) {
				appendFridaLog('[!] Process parameters not provided..');
				return;
			} else if (ProcId.length > 0 && ProcName.length > 0) {
				queryProc = ProcId;
			} else {
				if (!ProcId || 0 === ProcId.length) {
					queryProc = ProcName;
				} else {
					queryProc = ProcId;
				}
			}

			// Search active processes
			var resultArray = [];
			data.find(function (element) {
				var Result = [];
				if (element.name.includes(queryProc) || element.pid == queryProc) {
					resultArray.push(element);
				}
			})

			// Do we have a single match?
			if (resultArray.length == 0) {
				appendFridaLog('[!] Process not found..');
				return;
			} else if (resultArray.length > 1) {
				appendFridaLog('[!] Ambiguous process match..');
				for (var i = 0; i < resultArray.length; i++) {
					appendFridaLog('PID: ' + resultArray[i].pid + ', Name: ' + resultArray[i].name);
				}
				return;
			} else {
				appendFridaLog('[+] Injecting => PID: ' + resultArray[0].pid + ', Name: ' + resultArray[0].name);
				inject(resultArray[0].pid).catch(e => {
					appendFridaLog(e);
				});
			}
		}).catch((err) => {
			appendFridaLog(`[!] Error: ${err.message}`);
		});

	} else {
		appendFridaLog('[!] Already attached to a process..');
	}
});

// -= Shim for start invocation =-

ipc.on('start-process-shim', async (event, message) => {
	if (session == null) {
		appendFridaLog('[?] Attempting process start..');
		var ProcPath = message[0];
		var ProcAgrs = message[1];
		if (!ProcPath || 0 === ProcPath.length) {
			appendFridaLog('[!] Process parameters not provided..');
			return;
		} else {
			start(ProcPath, ProcAgrs).catch(e => {
				appendFridaLog(e);
				return;
			});
		}
	} else {
		appendFridaLog('[!] Already attached to a process..');
	}
});

// -= Shim for trace invocation =-

async function trace(scriptBody) {
	if (session != null) {
		if (script != null) {
			script.unload();
			script = await session.createScript(scriptBody);
			script.message.connect(message => {
				if (message.type == "send") {
					ChangeLogExclusive(logMutex, 'Append', "[>] Received Graphviz trace data");
					// Send it back to trace window
					traceSender.postMessage(message.payload);
				} else {
					ChangeLogExclusive(logMutex, 'Append', "[!] Runtime error: " + message.stack);
				}
				setTimeout(function () {
					if (RunningLog.length > 0) {
						ChangeLogExclusive(logMutex, 'Write', null);
					}
				}, 500);
			});
			appendFridaLog('\n[+] Current script unloaded..');
			appendFridaLog('    |_ Graphviz tracer loaded\n');
			await script.load();
		} else {
			appendFridaLog('[!] Not currently attached..');
		}
	} else {
		appendFridaLog('[!] Not currently attached..');
	}
}

// Pages
//////////////////////////////////////////////////

// -= Device Selector =-

document.getElementById("setDevice").onclick = function () {
	const modalPath = path.join('file://', __dirname, 'device.html');
	let ProcWin = new BrowserWindow({
		contextIsolation: false,
		width: 420,
		height: 600,
		frame: false,
		resizable: false,
		show: false,
		backgroundColor: '#E0E1E2',
		webPreferences: {
			nodeIntegration: true,
			nodeIntegrationInWorker: true,
			enableRemoteModule: true,
			contextIsolation: false,
			webviewTag: true,
			additionalArguments: wrapExtraArgs([deviceId])
		}
	})

	ProcWin.loadURL(modalPath);
	ProcWin.once('ready-to-show', () => {
		setTimeout(function () {
			ProcWin.show();
			ProcWin.focus();
		}, 50);
	});
	ProcWin.on('close', function () { ProcWin = null })
}

ipc.on('new-device', async (event, message) => {
	// Do we need to unregister a current remote socket?
	if (deviceId.startsWith("socket@")) {
		var dm = await frida.getDeviceManager();
		dm.removeRemoteDevice(deviceId.split('@')[1]);
	}

	// Do we need to register a new remote socket?
	if (message.startsWith("socket@")) {
		var dm = await frida.getDeviceManager();
		var devID = await dm.addRemoteDevice(message.split('@')[1]);
		deviceId = devID.id;
	} else {
		deviceId = message;
	}
});

// -= Process Listing =-

document.getElementById("FridaProc").onclick = function () {
	const modalPath = path.join('file://', __dirname, 'proc.html');
	let ProcWin = new BrowserWindow({
		contextIsolation: false,
		width: 570,
		height: 600,
		frame: false,
		resizable: false,
		show: false,
		backgroundColor: '#E0E1E2',
		webPreferences: {
			nodeIntegration: true,
			nodeIntegrationInWorker: true,
			enableRemoteModule: true,
			contextIsolation: false,
			webviewTag: true,
			additionalArguments: wrapExtraArgs([deviceId])
		}
	})

	ProcWin.loadURL(modalPath);
	ProcWin.once('ready-to-show', () => {
		setTimeout(function () {
			ProcWin.show();
			ProcWin.focus();
		}, 50);
	});
	ProcWin.on('close', function () { ProcWin = null })
}

// -= Instrument Manager =-

document.getElementById("FridaAttach").onclick = function () {
	const modalPath = path.join('file://', __dirname, 'instrument.html');
	let ProcWin = new BrowserWindow({
		contextIsolation: false,
		width: 420,
		height: 585,
		frame: false,
		resizable: false,
		show: false,
		backgroundColor: '#E0E1E2',
		webPreferences: {
			nodeIntegration: true,
			nodeIntegrationInWorker: true,
			enableRemoteModule: true,
			contextIsolation: false,
			webviewTag: true
		}
	})

	ProcWin.loadURL(modalPath);
	ProcWin.once('ready-to-show', () => {
		setTimeout(function () {
			ProcWin.show();
			ProcWin.focus();
		}, 50);
	});
	ProcWin.on('close', function () { ProcWin = null })
}

// -= About =-

document.getElementById("FermionAbout").onclick = function () {
	const modalPath = path.join('file://', __dirname, 'about.html');
	let ProcWin = new BrowserWindow({
		contextIsolation: false,
		width: 460,
		height: 270,
		frame: false,
		resizable: false,
		show: false,
		backgroundColor: '#E0E1E2',
		webPreferences: {
			nodeIntegration: true,
			nodeIntegrationInWorker: true,
			enableRemoteModule: true,
			contextIsolation: false,
			webviewTag: true,
			additionalArguments: wrapExtraArgs([deviceId])
		}
	})

	ProcWin.loadURL(modalPath);
	ProcWin.once('ready-to-show', () => {
		setTimeout(function () {
			ProcWin.show();
			ProcWin.focus();
		}, 50);
	});
	ProcWin.on('close', function () { ProcWin = null })
}

// -= JS API Docs =-

document.getElementById("FermionDocs").onclick = function () {
	const modalPath = path.join('file://', __dirname, 'docs.html');
	let ProcWin = new BrowserWindow({
		contextIsolation: false,
		width: 800,
		height: 800,
		frame: false,
		resizable: false,
		show: false,
		backgroundColor: '#E0E1E2',
		webPreferences: {
			nodeIntegration: true,
			nodeIntegrationInWorker: true,
			enableRemoteModule: true,
			contextIsolation: false,
			webviewTag: true
		}
	})

	ProcWin.loadURL(modalPath);
	ProcWin.once('ready-to-show', () => {
		setTimeout(function () {
			ProcWin.show();
			ProcWin.focus();
		}, 50);
	});
	ProcWin.on('close', function () { ProcWin = null })
}

// -= Trace =-

let TraceWin = null;
document.getElementById("FermionTools").onclick = function () {
	const modalPath = path.join('file://', __dirname, 'trace.html');
	if (sessionPID == null || sessionPID.length == 0) {
		sessionPID = "null";
	}
	TraceWin = new BrowserWindow({
		contextIsolation: false,
		width: 425,
		height: 600,
		frame: false,
		resizable: false,
		show: false,
		backgroundColor: '#E0E1E2',
		webPreferences: {
			nodeIntegration: true,
			nodeIntegrationInWorker: true,
			enableRemoteModule: true,
			contextIsolation: false,
			webviewTag: true,
			additionalArguments: wrapExtraArgs([sessionPID])
		}
	})

	TraceWin.loadURL(modalPath);
	TraceWin.once('ready-to-show', () => {
		setTimeout(function () {
			TraceWin.show();
			TraceWin.focus();
		}, 50);
	});
	TraceWin.on('close', function () { TraceWin = null })
}

// Create IPC sender
const traceSender = new BroadcastChannel('trace-data-send');

// Invoke trace shim
traceSender.onmessage = function (message) {
	if (message.data == "STOP") {
		appendFridaLog('\n[+] Graphviz tracer will be unloaded..');
		appendFridaLog('    |_ Reloading script in Monaco editor\n');
		document.getElementById("FridaReload").click();
	} else {
		trace(message.data);
	}
}

// Logging
//////////////////////////////////////////////////

function appendFridaLog(data) {
	var FridaOut = document.getElementById('FridaOut');
	FridaOut.value += (data + "\n");

	// DIY garbage collection
	// |-> If the textarea grows too large it locks up the app
	var aFridaOut = FridaOut.value.split("\n");
	var iMaxLen = 5000; // max line count in textarea
	if (aFridaOut.length > iMaxLen) {
		var iRemCount = aFridaOut.length - iMaxLen;
		aFridaOut.splice(0, iRemCount);
		FridaOut.value = aFridaOut.join("\n");
	}

	FridaOut.scrollTop = FridaOut.scrollHeight;
}

function ChangeLogExclusive(mutex, locktype, data) {
	return mutex.promise()
		.then(function (mutex) {
			mutex.lock();
			if (locktype == "Append") {
				RunningLog.push(data);
			} else if (locktype == "Write") {
				appendFridaLog(RunningLog.join("\n"));
				RunningLog = [];
			}
		})
		.then(function (res) {
			mutex.unlock();
			return res;
		})
		.catch(function (e) {
			mutex.unlock();
			throw e;
		});
}

// Monaco Editor
//////////////////////////////////////////////////

function LocalLoadLang(url, method) {
	var request = new XMLHttpRequest();
	return new Promise(function (resolve, reject) {
		request.onreadystatechange = function () {
			if (request.readyState !== 4) return;
			if (request.status >= 200 && request.status < 300) {
				resolve(request);
			} else {
				reject({
					status: request.status,
					statusText: request.statusText
				});
			}
		};
		request.open(method || 'GET', url, true);
		request.send();
	});
};

function setMonacoTheme() {
	var theme = document.getElementById("MonacoThemeSelect").value;
	var refCodeContainer = document.getElementById("Container");
	if (theme == "idleFingers") {
		monaco.editor.defineTheme("idleFingers", idleFingers);
		monaco.editor.setTheme("idleFingers");
	} else if (theme == "Cobalt") {
		monaco.editor.defineTheme("Cobalt", Cobalt);
		monaco.editor.setTheme("Cobalt");
	} else if (theme == "MerbivoreSoft") {
		monaco.editor.defineTheme("MerbivoreSoft", MerbivoreSoft);
		monaco.editor.setTheme("MerbivoreSoft");
	} else if (theme == "Katzenmilch") {
		monaco.editor.defineTheme("Katzenmilch", Katzenmilch);
		monaco.editor.setTheme("Katzenmilch");
	} else if (theme == "Monokai") {
		monaco.editor.defineTheme("Monokai", Monokai);
		monaco.editor.setTheme("Monokai");
	} else if (theme == "Solarized-Dark") {
		monaco.editor.defineTheme("SolarizedDark", SolarizedDark);
		monaco.editor.setTheme("SolarizedDark");
	} else if (theme == "Solarized-Light") {
		monaco.editor.defineTheme("SolarizedLight", SolarizedLight);
		monaco.editor.setTheme("SolarizedLight");
	} else if (theme == "Birds-Of-Paradise") {
		monaco.editor.defineTheme("BirdsOfParadise", BirdsOfParadise);
		monaco.editor.setTheme("BirdsOfParadise");
	} else if (theme == "Clouds") {
		monaco.editor.defineTheme("Clouds", Clouds);
		monaco.editor.setTheme("Clouds");
	} else if (theme == "Kuroir") {
		monaco.editor.defineTheme("Kuroir", Kuroir);
		monaco.editor.setTheme("Kuroir");
	} else if (theme == "NightOwl") {
		monaco.editor.defineTheme("NightOwl", NightOwl);
		monaco.editor.setTheme("NightOwl");
	} else if (theme == "Textmate") {
		monaco.editor.defineTheme("Textmate", Textmate);
		monaco.editor.setTheme("Textmate");
	} else if (theme == "VSCode") {
		monaco.editor.setTheme("vs");
	} else if (theme == "VSCode-Dark") {
		monaco.editor.setTheme("vs-dark");
	} else if (theme == "VSCode-HighContrast") {
		monaco.editor.setTheme("hc-black");
	} else if (theme == "Amy") {
		monaco.editor.defineTheme("Amy", Amy);
		monaco.editor.setTheme("Amy");
	} else if (theme == "Oceanic Next") {
		monaco.editor.defineTheme("Oceanic-Next", OceanicNext);
		monaco.editor.setTheme("Oceanic-Next");
	} else if (theme == "Tomorrow Night Blue") {
		monaco.editor.defineTheme("Tomorrow-Night-Blue", TomorrowNightBlue);
		monaco.editor.setTheme("Tomorrow-Night-Blue");
	} else if (theme == "Vibrant Ink") {
		monaco.editor.defineTheme("Vibrant-Ink", VibrantInk);
		monaco.editor.setTheme("Vibrant-Ink");
	}
}

// UI Handler
//////////////////////////////////////////////////

function exitFermion() {
	var CurrWnd = remote.getCurrentWindow();
	CurrWnd.close();
}

document.getElementById("FermionDevTools").onclick = function () {
	var CurrWnd = remote.getCurrentWindow();
	CurrWnd.webContents.openDevTools({ mode: 'detach' });
}

document.getElementById("FermionOpen").onclick = function () {
	dialog.showOpenDialog(
		{
			properties: ['openFile'],
			title: "Fermion Open File",
		}
	).then(result => {
		if (result.filePaths.length == 0) {
			return;
		} else {
			fs.readFile(result.filePaths[0], 'utf-8', (err, data) => {
				if (err) {
					appendFridaLog("[!] Error opening file: " + err.message);
					return;
				} else {
					appendFridaLog("[+] File opened..");
					appendFridaLog("    |-> Path: " + result.filePaths[0]);
				}
				MonacoCodeEditor.setValue(data);
				// Set global filepath on success
				currentFilePath = result.filePaths[0];
			});
		}
	}).catch(err =>{
		appendFridaLog("[!] Error opening file: " + err)
	})
}

document.getElementById("FermionSave").onclick = function () {
	dialog.showSaveDialog(
		{
			title: "Fermion Save File",
		}
	).then(result => {
		if (result.filePath) {
			content = MonacoCodeEditor.getValue();
			fs.writeFile(result.filePath, content, (err) => {
				if (err) {
					appendFridaLog("[!] Error saving file: " + err.message)
					return;
				} else {
					appendFridaLog("[+] File saved..");
					appendFridaLog("    |-> Path: " + result.filePath);
				}
				// Set global filepath on success
				currentFilePath = result.filePath;
			});
		}
	}).catch(err =>{
		appendFridaLog("[!] Error saving file: " + err)
	})
}

document.getElementById("getDeviceDetail").onclick = function () {
	appendFridaLog("\n[>] Device --> " + deviceId);
	frida.getDevice(deviceId).then(dev => {
		appendFridaLog("    |_ Device Name : " + dev.name);
		dev.querySystemParameters().then(result => {
			if (result.hasOwnProperty("os")) {
				if (result.os.hasOwnProperty("name")) {
					appendFridaLog("    |_ Platform    : " + result.os.name);
				}
				if (result.os.hasOwnProperty("version")) {
					appendFridaLog("    |_ Version     : " + result.os.version);
				}
			}
			if (result.hasOwnProperty("arch")) {
				appendFridaLog("    |_ Arch        : " + result.arch);
			}
			if (result.hasOwnProperty("access")) {
				appendFridaLog("    |_ Access      : " + result.access);
			}
			if (result.hasOwnProperty("name")) {
				appendFridaLog("    |_ Host Name   : " + result.name + "\n");
			}
		}).catch(err =>{
			appendFridaLog("[!] Failed to enumerate device properties: " + err + "\n");
		});
	}).catch(err =>{
		appendFridaLog("[!] Failed to acquire device context: " + err + "\n");
	});
}

document.getElementById("FermionMonacoWrap").onclick = function () {
	// Toggle the current state
	var wrapState = document.getElementById("FermionMonacoWrap");
	if (wrapState.classList.contains("checked") == false) {
		MonacoCodeEditor.updateOptions({ wordWrap: "on" });
	} else {
		MonacoCodeEditor.updateOptions({ wordWrap: "off" });
	}
}

// Trap keybinds
//////////////////////////////////////////////////

document.addEventListener("keydown", function (e) {
	if ((window.navigator.platform.match("Mac") ? e.metaKey : e.ctrlKey) && e.keyCode == 83) {
		e.preventDefault();

		// Do we currently have a known file path?
		if (currentFilePath == null) {
			// Trigger the save function
			document.getElementById("FermionSave").click();
		} else {
			// Overwrite known file
			dialog.showMessageBox(
				{
					type: "warning",
					buttons: ["Yes", "No"],
					defaultId: 1,
					title: "Save File",
					message: "Overwrite existing file?",
					detail: currentFilePath,
					cancelId: 1,
				}
			).then(result => {
				if (result.response == 0) {
					content = MonacoCodeEditor.getValue();
					fs.writeFile(currentFilePath, content, (err) => {
						if (err) {
							appendFridaLog("[!] Error saving file: " + err.message);
							appendFridaLog("    |-> Path: " + currentFilePath);
						} else {
							appendFridaLog("[+] File saved..");
							appendFridaLog("    |-> Path: " + currentFilePath);
						}
					})
				}
			})
		}
	}
}, false);

document.addEventListener("keydown", function (e) {
	if ((window.navigator.platform.match("Mac") ? e.metaKey : e.ctrlKey) && e.keyCode == 79) {
		e.preventDefault();
		// Trigger the save function
		document.getElementById("FermionOpen").click();
	}
}, false);

document.addEventListener("keydown", function (e) {
	if ((window.navigator.platform.match("Mac") ? e.metaKey : e.ctrlKey) && e.keyCode == 84) {
		e.preventDefault();
		// Trigger script reload
		document.getElementById("FridaReload").click();
	}
}, false);