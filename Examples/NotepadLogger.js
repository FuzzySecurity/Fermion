//------------------------------------------------------//
// Using native function calls to log to notepad window //
//------------------------------------------------------//

// Native function pointers
//-----------------------
var pFindWindowA = Module.findExportByName("User32.dll","FindWindowA");
var pFindWindowExA = Module.findExportByName("User32.dll","FindWindowExA");
var pSendMessageA = Module.findExportByName("User32.dll","SendMessageA");
var pCloseHandle = Module.findExportByName("Kernel32.dll","CloseHandle");
var pAmsiScanBuff = Module.findExportByName('amsi.dll', 'AmsiScanBuffer')

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

var fFindWindowExA = new NativeFunction(
    pFindWindowExA,
    "pointer",
    [
        "pointer",
        "pointer",
        "pointer",
        "pointer"
    ]
);

var fSendMessageA = new NativeFunction(
    pSendMessageA,
    "pointer",
    [
        "pointer",
        "uint",
        "pointer",
        "pointer"
    ]
);

var fCloseHandle = new NativeFunction(
    pCloseHandle,
    "bool",
    [
        "pointer"
    ]
);

// Enums
//-----------------------
var AMSI_RESULT = {
    AMSI_RESULT_CLEAN: 0,
    AMSI_RESULT_NOT_DETECTED: 1,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START: 0x4000,
    AMSI_RESULT_BLOCKED_BY_ADMIN_END: 0x4FFF,
    AMSI_RESULT_DETECTED: 0x8000
}

// Helpers
//-----------------------
function AmsiResult(flag) {
    if (flag == AMSI_RESULT.AMSI_RESULT_CLEAN) return "AMSI_RESULT_CLEAN";
    if (flag == AMSI_RESULT.AMSI_RESULT_NOT_DETECTED) return "AMSI_RESULT_NOT_DETECTED";
    if (flag == AMSI_RESULT.AMSI_RESULT_BLOCKED_BY_ADMIN_START) return "AMSI_RESULT_BLOCKED_BY_ADMIN_START";
    if (flag == AMSI_RESULT.AMSI_RESULT_BLOCKED_BY_ADMIN_END) return "AMSI_RESULT_BLOCKED_BY_ADMIN_END";
    if (flag == AMSI_RESULT.AMSI_RESULT_DETECTED) return "AMSI_RESULT_DETECTED";
}

function logToNotepad(input) {
    var hWindow;

    // Find notepad window
    var lpWindowName = Memory.allocAnsiString("Untitled - Notepad");
    hWindow = fFindWindowA(ptr(0), lpWindowName);
    if (hWindow == 0) {
        var lpWindowName = Memory.allocAnsiString("*Untitled - Notepad");
        hWindow = fFindWindowA(ptr(0), lpWindowName);
        if (hWindow == 0) {
            send("[!] Failed to get a handle to notepad..")
            return;
        }
    }

    // Find window class
    var lpszClass = Memory.allocAnsiString("EDIT");
    var hClass = fFindWindowExA(hWindow, ptr(0), lpszClass, ptr(0));

    // Send message
    var EM_REPLACESEL = 0x00c2;
    var lParam = Memory.allocAnsiString(input + "\n");
    var lResult = fSendMessageA(hClass, EM_REPLACESEL, ptr(1), lParam);

    // Free handles
    fCloseHandle(hClass);
    fCloseHandle(hWindow);
}

// Hook
//-----------------------
Interceptor.attach(pAmsiScanBuff, {
    onEnter: function (args) {
        logToNotepad("[+] Called AmsiScanBuffer")

        // HAMSICONTEXT -> tagHAMSICONTEXT
        //---------------------------------
        // typedef struct tagHAMSICONTEXT {
        //   DWORD        Signature;          // "AMSI" or 0x49534D41
        //   PWCHAR       AppName;            // set by AmsiInitialize
        //   IAntimalware *Antimalware;       // set by AmsiInitialize
        //   DWORD        SessionCount;       // increased by AmsiOpenSession
        // } _HAMSICONTEXT, *_PHAMSICONTEXT;
        //---------------------------------
        // Note that on x64 there is 4-byte padding after tagHAMSICONTEXT.Signature
        this.AppName = (((args[0]).add(8)).readPointer()).readUtf16String();

        // We divide the BuffLen by 2 since it is a Utf-16 string
        this.Length = (args[2].toInt32() / 2);

        // Store the result ptr as that will be populated in onLeave
        this.AmsiResult = args[5];

        // Store the string that is scanned
        this.Buffer = args[1].readUtf16String();
    },

    onLeave: function (retval) {
        logToNotepad("    |-> tagHAMSICONTEXT.App : " + this.AppName)
        logToNotepad("    |-> AmsiResult          : " + AmsiResult(this.AmsiResult.readInt()))
        logToNotepad("    |-> Buffer Len          : " + this.Length)
        logToNotepad("    |-> Buffer              : \n\n" + this.Buffer + "\n")
    }
});