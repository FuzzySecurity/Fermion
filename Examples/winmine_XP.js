//--------------------------------------------------//
// Solve XP minesweeper of any size & configuration //
//--------------------------------------------------//

// NOTE: You should attach to minesweeper
// not spawn it.

// Native pointers
//-----------------------
var pWinminBase = Module.getBaseAddress("Winmine_9c45d38b74634c9ded60bec640c5c3ca.exe");
var pMineStruct = pWinminBase.add(0x5330);
var pFindWindowA = Module.findExportByName("User32.dll","FindWindowA");
var pGetWindowRect = Module.findExportByName("User32.dll","GetWindowRect");
var pSetCursorPos = Module.findExportByName("User32.dll","SetCursorPos");
var pMouseEvent = Module.findExportByName("User32.dll","mouse_event");
var pSetForegroundWindow = Module.findExportByName("User32.dll","SetForegroundWindow");

// Function prototypes
//-----------------------
var fFindWindowA = new NativeFunction(
    pFindWindowA,
    "pointer",
    [
        "pointer",
        "pointer"
    ]
);

var fGetWindowRect = new NativeFunction(
    pGetWindowRect,
    "bool",
    [
        "pointer",
        "pointer"
    ]
);

var fSetCursorPos = new NativeFunction(
    pSetCursorPos,
    "bool",
    [
        "uint32",
        "uint32"
    ]
);

var fMouseEvent = new NativeFunction(
    pMouseEvent,
    "void",
    [
        "uint32",
        "uint32",
        "uint32",
        "uint32",
        "pointer"
    ]
);

var fSetForegroundWindow = new NativeFunction(
    pSetForegroundWindow,
    "bool",
    [
        "pointer"
    ]
);

// Coordinate array
//-----------------------
var coValArray = new Array();
function coVal(x, y, val) {
    this.x = x;
    this.y = y;
    this.val = val;
}

// Auto-Solver
//-----------------------
function solveBoard() {
    // Get window handle
    var lpWindowName = Memory.allocAnsiString("Minesweeper");
    var hWnd = fFindWindowA(ptr(0), lpWindowName);
    if (hWnd == 0) {
        send("[!] Failed to get window handle..");
        return;
    }

    // Set as forground
    fSetForegroundWindow(hWnd);

    // Alloc tagRECT
    var ptagRECT = Memory.alloc(16);
    var bCallRes = fGetWindowRect(hWnd, ptagRECT);
    if (!bCallRes) {
        send("[!] Failed to get window tagRECT..");
        return;
    }

    // Get coordinates of the top left tile
    var topLeftX = ptagRECT.readU32() + 21;
    var topLeftY = ptagRECT.add(4).readU32() + 109;

    // Loop coValArray -> move mouse -> click
    var bClick = false;
    for (var i = 0; i < coValArray.length; i++) {
        var tile = coValArray[i];
        // Only process block we need to click
        if (tile.val == 0) {
            // Calculate offset of tile
            var tileX = topLeftX + (tile.x * 16);
            var tileY = topLeftY + (tile.y * 16);
            // Move cursor and click
            fSetCursorPos(tileX, tileY);
            fMouseEvent(0x0002, 0, 0, 0, ptr(0));
            fMouseEvent(0x0004, 0, 0, 0, ptr(0));
            // There is some kind of bug for the very first click
            // you basically have to click twice..
            if (!bClick) {
                fMouseEvent(0x0002, 0, 0, 0, ptr(0));
                fMouseEvent(0x0004, 0, 0, 0, ptr(0));
                bClick = true;
            }
            
            // If you want to see it move
            //Thread.sleep(0.01);
        }
    }
}

// Parse board info
//-----------------------
var iBombCount = pMineStruct.readU32();
var iSizeX = pMineStruct.add(4).readU32();
var iSizeY = pMineStruct.add(8).readU32();
send("[+] Game set, match..");
send("    |-> Bombs  : " + iBombCount);
send("    |-> Size-X : " + iSizeX);
send("    |-> Size-Y : " + iSizeY);
send("    |-> Board  : \n");

var iBoardOffset = 0x31;
for (var i = 0; i < iSizeY; i++) {
    // Parse board data
    var sRow = "";
    var rowData = pMineStruct.add(iBoardOffset + (i*32)).readByteArray(iSizeX);
    var uintArray = new Uint8Array(rowData);
    for (var y=0; y<uintArray.length; y++) {
        if (uintArray[y] == 0x0f) {
            sRow += " ~ ";
            coValArray.push(new coVal(y, i, 0));
        } else {
            sRow += " X ";
            coValArray.push(new coVal(y, i, 1));
        }
    }
    send(sRow);
}

// Solve
//-----------------------
send("\n[+] Auto-solving in 3, 2, 1..");
Thread.sleep(3);
solveBoard();