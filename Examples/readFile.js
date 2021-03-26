// Native function ptr's
//=====
var pReadFile = Module.findExportByName("kernel32.dll", "ReadFile");
var pGetFileInformationByHandleEx = Module.findExportByName("kernel32.dll", "GetFileInformationByHandleEx");

// Function defs
//=====
var fGetFileInformationByHandleEx = new NativeFunction(
    pGetFileInformationByHandleEx,
    "bool",
    [
        "pointer",
        "uint",
        "pointer",
        "uint"
    ]
);

// Helpers
//=====
var iPtrSize;
if (Process.arch == "x64") {
    iPtrSize = 0x8;
} else {
    iPtrSize = 0x4;
}

function getNameFromHandle(hFile) {
    var lpFileInformation = Memory.alloc(0x200);
    // 0x2 -> FILE_NAME_INFO
    var callRes = fGetFileInformationByHandleEx(hFile, 0x2, lpFileInformation, 0x200);
    if (callRes) {
        send("    |_ hFile                : " + (lpFileInformation.add(0x4)).readUtf16String());
    } else {
        send("    |_ hFile                : N/A");
    }
}

function getOVERLAPPEDFromPtr(pOVERLAPPED) {
    var pInternal = pOVERLAPPED.readPointer();
    var pInternalHigh = (pOVERLAPPED.add(iPtrSize)).readPointer();
    var iOffset = (pOVERLAPPED.add(iPtrSize*2)).readU32();
    var iOffsetHigh = (pOVERLAPPED.add(iPtrSize*2+4)).readU32();
    var pPointer = (pOVERLAPPED.add(iPtrSize*2)).readPointer();
    var hEvent = (pOVERLAPPED.add(iPtrSize*2+8)).readPointer();
    send("    |_ lpOverlapped");
    if (pInternal == 0x103) {
        send("       |_ Internal          : IO_STATUS_PENDING");
    } else if (pInternal == 0x0) {
        send("       |_ Internal          : IO_STATUS_SUCCESS");
    } else {
        send("       |_ Internal          : " + pInternal);
    }
    send("       |_ InternalHigh      : " + pInternalHigh);
    send("          |_ Offset            : " + iOffset);
    send("          |_ OffsetHigh        : " + iOffsetHigh);
    send("          |_ Pointer           : " + pPointer);
    send("       |_ hEvent            : " + hEvent);
}

function getIO_STATUS(pOVERLAPPED) {
    return pOVERLAPPED.readPointer();
}

function getIO_SIZE(pOVERLAPPED) {
    return (pOVERLAPPED.add(iPtrSize)).readPointer();
}

// Hooks
//=====
Interceptor.attach(pReadFile, {
    onEnter: function (args) {
        send("\n>>> ReadFile");
        getNameFromHandle(args[0]);
        send("    |_ lpBuffer             : " + args[1]);
        send("    |_ nNumberOfBytesToRead : " + args[2]);
        send("    |_ lpNumberOfBytesRead  : " + args[3]);
        if (args[4].toInt32() == 0) {
            send("    |_ lpOverlapped         : " + args[4]);
        } else {
            getOVERLAPPEDFromPtr(args[4]);
        }

        // Save ptr's for return inspection
        this.buffPtr = args[1];
        this.buffLen = args[2];
        this.overlapped = args[4];
    },
    onLeave: function (retval) {
        send("\n<<< ReadFile");
        if (this.overlapped.toInt32() != 0) {
            getOVERLAPPEDFromPtr(this.overlapped);
        }
        if (retval) {
            send("    |_ Complete             : true");
            send("    |_ Data                 : \n" + hexdump(this.buffPtr,  {length:this.buffLen.toInt32()}));
        } else {
            send("    |_ Complete             : false");
        }
    }
});