//--------------------//
// AMSI Introspection //
//--------------------//

// Native function pointer
var pAmsiScanBuff = Module.findExportByName('amsi.dll', 'AmsiScanBuffer')

// Enum
var AMSI_RESULT = {
    AMSI_RESULT_CLEAN: 0,
    AMSI_RESULT_NOT_DETECTED: 1,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START: 0x4000,
    AMSI_RESULT_BLOCKED_BY_ADMIN_END: 0x4FFF,
    AMSI_RESULT_DETECTED: 0x8000
}

// Helpers
function AmsiResult(flag) {
    if (flag == AMSI_RESULT.AMSI_RESULT_CLEAN) return "AMSI_RESULT_CLEAN";
    if (flag == AMSI_RESULT.AMSI_RESULT_NOT_DETECTED) return "AMSI_RESULT_NOT_DETECTED";
    if (flag == AMSI_RESULT.AMSI_RESULT_BLOCKED_BY_ADMIN_START) return "AMSI_RESULT_BLOCKED_BY_ADMIN_START";
    if (flag == AMSI_RESULT.AMSI_RESULT_BLOCKED_BY_ADMIN_END) return "AMSI_RESULT_BLOCKED_BY_ADMIN_END";
    if (flag == AMSI_RESULT.AMSI_RESULT_DETECTED) return "AMSI_RESULT_DETECTED";
}

// Hook
Interceptor.attach(pAmsiScanBuff, {
    onEnter: function (args) {
        send("[+] Called AmsiScanBuffer")

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
        send("    |-> tagHAMSICONTEXT.App : " + this.AppName)
        send("    |-> AmsiResult          : " + AmsiResult(this.AmsiResult.readInt()))
        send("    |-> Buffer Len          : " + this.Length)
        send("    |-> Buffer              : \n\n" + this.Buffer + "\n")
    }
});