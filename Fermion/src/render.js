// Pre-Reqs
//////////////////////////////////////////////////
const electron = require('electron');
const remote = electron.remote;
const nativeImage = electron.nativeImage;
const BrowserWindow = remote.BrowserWindow;
const frida = require('frida');
const path = require('path');
var MutexPromise = require('mutex-promise');
var app = require('electron').remote;
var dialog = app.dialog;
var fs = require('fs');

// Overwrite default node.js prop to get Jquery working
window.$ = window.jQuery = require('jquery');

// Frida
//////////////////////////////////////////////////

// Global vars
var MonacoCodeEditor;
let script = null;
let session = null;
let logMutex = new MutexPromise('48011b2b9a930ee19e26320e5adbffa2e309663c');
let RunningLog = [];
var deviceId = 'local';
var currentFilePath = null;

// Attach
async function inject(AttachTo) {
	// Exit on process termination
	process.on('SIGTERM', stop);
	process.on('SIGINT', stop);

	// Attach and load script
	device = await frida.getDevice(deviceId);
	session = await device.attach(AttachTo);
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

// Start
async function start(Path, Args) {
	// Exit on process termination
	process.on('SIGTERM', stop);
	process.on('SIGINT', stop);

	// Attach and load script
	device = await frida.getDevice(deviceId);
	if (!Args || 0 === Args.length) {
		procID = await device.spawn(Path);
	} else {
		procID = await device.spawn([Path,Args]);
	}
	session = await device.attach(procID);
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

// Stop
function stop() {
	script.unload();
}

// Detach
function onDetached(reason) {
	if (session != null) {
		session = null;
	}
	appendFridaLog(`[+] Exit Reason: ${reason}`);
}

// Process listing
async function getProcList() {
	let currentDevice = await frida.getDevice(deviceId);
	let Applications = await currentDevice.enumerateProcesses();
	return Applications;
}

// UI Frida hooks
//////////////////////////////////////////////////
function appendFridaLog(data) {
	var FridaOut = document.getElementById('FridaOut');
	FridaOut.value += (data + "\n");
	FridaOut.scrollTop = FridaOut.scrollHeight;
}

document.getElementById("FridaAttach").onclick = function () {
	if (session == null) {
		appendFridaLog('[?] Attempting process attach..');
		getProcList().then(data => {
			// What are we searching for?
			var ProcId = document.getElementById("procID").value;
			var ProcName = document.getElementById("procName").value
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
}

document.getElementById("FridaStart").onclick = function () {
	if (session == null) {
		appendFridaLog('[?] Attempting process start..');
		var ProcPath = document.getElementById("procPath").value;
		var ProcAgrs = document.getElementById("procArgs").value;
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
}

document.getElementById("FridaDetach").onclick = function () {
	if (session != null) {
		appendFridaLog('[+] Detaching..');
		session.detach();
		session = null;
	} else {
		appendFridaLog('[!] Not currently attached..');
	}
}

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

document.getElementById("FridaProc").onclick = function () {
	const modalPath = path.join('file://', __dirname, 'proc.html');
	let ProcWin = new BrowserWindow({
		width: 400,
		height: 600,
		frame: false,
		resizable: false,
		backgroundColor: '#464646',
		webPreferences: { nodeIntegration: true, enableRemoteModule: true }
	})
	ProcWin.loadURL(modalPath+"?deviceId="+btoa(deviceId));
	ProcWin.once('ready-to-show', () => {
		ProcWin.show();
		ProcWin.focus();
	});
	ProcWin.on('close', function () { ProcWin = null })
}

async function updateDeviceList() {
	// Get dropdown array
	var dn = document.getElementById("deviceName");
	var currentDevice = dn.options[deviceName.selectedIndex].value;
	var dnArr = Array.from(dn.options).map(elem => elem.text);

	// Get device array
	var dm = frida.getDeviceManager();
	var dev = await dm.enumerateDevices();
	var devArr = dev.map(elem => elem.id);

	// Does the current device still exist?
	if (!devArr.includes(currentDevice)) {
		// Local is always a valid target
		dn.selectedIndex = 0;
		deviceId = 'local';
	}

	// Remove stale entries from the dropdown
	dnArr.forEach(function(elem) {
		if (!devArr.includes(elem)) {
			$(`#deviceName option:contains("${elem}")`).remove()
		}
	})

	// Add new entries to the dropdown
	devArr.forEach(function(elem) {
		if (!dnArr.includes(elem) && elem != "tcp" && elem != "socket") {
			$("#deviceName").append(new Option(elem))
		}
	})
}

document.getElementById("deviceName").onchange = function () {
	deviceId = this.value;
}

// Menu UI hooks
//////////////////////////////////////////////////
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

document.getElementById("FermionDevTools").onclick = function () {
	var CurrWnd = remote.getCurrentWindow();
	CurrWnd.webContents.openDevTools({ mode: 'detach' });
}

document.getElementById("FermionAbout").onclick = function () {
	const modalPath = path.join('file://', __dirname, 'about.html');
	let AboutWin = new BrowserWindow({
		width: 400,
		height: 200,
		frame: false,
		show: false,
		resizable: false,
		backgroundColor: '#ff4757',
		webPreferences: { nodeIntegration: true, enableRemoteModule: true }
	})
	AboutWin.loadURL(modalPath);
	AboutWin.once('ready-to-show', () => {
		AboutWin.show();
		AboutWin.focus();
	});
	AboutWin.on('close', function () { AboutWin = null })
}

document.getElementById("FermionExit").onclick = function () {
	var CurrWnd = remote.getCurrentWindow();
	CurrWnd.close();
}

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
	}
}

document.getElementById("FermionMonacoWrap").onclick = function () {
	var wrapState = document.getElementById("FermionMonacoWrap");
	if (wrapState.checked == true) {
		MonacoCodeEditor.updateOptions({ wordWrap: "on" });
	} else {
		MonacoCodeEditor.updateOptions({ wordWrap: "off" });
	}
}

// Log Mutex
//////////////////////////////////////////////////
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

// UI hackery
//////////////////////////////////////////////////
function SetDynamicResize(MonacoObj) {
	// We need this hack because our collapsible sidebar
	// causes the viewpane to resize incorrectly
	var EditorCont = document.getElementById("container")
	var ViewWidth = document.querySelector("html").offsetWidth
	var SideBar = document.getElementById("sidebar")
	if (!SideBar.className || SideBar.className.length == 0) {
		var offset = { width: (ViewWidth - 260), height: EditorCont.offsetHeight }
	} else {
		var offset = { width: ViewWidth, height: EditorCont.offsetHeight }
	}
	MonacoObj.layout(offset);
}

// Monaco Load TypeScript FridaLang
//////////////////////////////////////////////////
var LocalLoadLang = function (url, method) {
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

// Trap Ctrl/Command-s / Ctrl/Command-o
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