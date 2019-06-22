//------------------------//
// Hooking COM Invocation //
//------------------------//

// Native function pointers
//-----------------------
var pCoGet = Module.findExportByName('Ole32.dll','CoGetClassObject')
var pStringFromCLSID = Module.findExportByName('Ole32.dll','StringFromCLSID')

// API prototype
//-----------------------
var fStringFromCLSID = new NativeFunction(
    pStringFromCLSID,
    "uint32",
    [
        "pointer",
        "pointer"
    ]
);

// Enums
//-----------------------
var CLSCTX = {
    CLSCTX_INPROC_SERVER : 0x1,
    CLSCTX_INPROC_HANDLER : 0x2,
    CLSCTX_LOCAL_SERVER : 0x4,
    CLSCTX_INPROC_SERVER16 : 0x8,
    CLSCTX_REMOTE_SERVER : 0x10,
    CLSCTX_INPROC_HANDLER16 : 0x20,
    CLSCTX_RESERVED1 : 0x40,
    CLSCTX_RESERVED2 : 0x80,
    CLSCTX_RESERVED3 : 0x100,
    CLSCTX_RESERVED4 : 0x200,
    CLSCTX_NO_CODE_DOWNLOAD : 0x400,
    CLSCTX_RESERVED5 : 0x800,
    CLSCTX_NO_CUSTOM_MARSHAL : 0x1000,
    CLSCTX_ENABLE_CODE_DOWNLOAD : 0x2000,
    CLSCTX_NO_FAILURE_LOG : 0x4000,
    CLSCTX_DISABLE_AAA : 0x8000,
    CLSCTX_ENABLE_AAA : 0x10000,
    CLSCTX_FROM_DEFAULT_CONTEXT : 0x20000,
    CLSCTX_ACTIVATE_32_BIT_SERVER : 0x40000,
    CLSCTX_ACTIVATE_64_BIT_SERVER : 0x80000
}

// Helpers
//-----------------------
function GetClsContextMask (enumval) {
    var ContextMask = [];

    // IIRC JS can't natively read bit masks
    if ( (enumval & CLSCTX.CLSCTX_INPROC_SERVER) == CLSCTX.CLSCTX_INPROC_SERVER) ContextMask.push("CLSCTX_INPROC_SERVER");
    if ( (enumval & CLSCTX.CLSCTX_INPROC_HANDLER) == CLSCTX.CLSCTX_INPROC_HANDLER) ContextMask.push("CLSCTX_INPROC_HANDLER");
    if ( (enumval & CLSCTX.CLSCTX_LOCAL_SERVER) == CLSCTX.CLSCTX_LOCAL_SERVER) ContextMask.push("CLSCTX_LOCAL_SERVER");
    if ( (enumval & CLSCTX.CLSCTX_INPROC_SERVER16) == CLSCTX.CLSCTX_INPROC_SERVER16) ContextMask.push("CLSCTX_INPROC_SERVER16");
    if ( (enumval & CLSCTX.CLSCTX_REMOTE_SERVER) == CLSCTX.CLSCTX_REMOTE_SERVER) ContextMask.push("CLSCTX_REMOTE_SERVER");
    if ( (enumval & CLSCTX.CLSCTX_INPROC_HANDLER16) == CLSCTX.CLSCTX_INPROC_HANDLER16) ContextMask.push("CLSCTX_INPROC_HANDLER16");
    if ( (enumval & CLSCTX.CLSCTX_RESERVED1) == CLSCTX.CLSCTX_RESERVED1) ContextMask.push("CLSCTX_RESERVED1");
    if ( (enumval & CLSCTX.CLSCTX_RESERVED2) == CLSCTX.CLSCTX_RESERVED2) ContextMask.push("CLSCTX_RESERVED2");
    if ( (enumval & CLSCTX.CLSCTX_RESERVED3) == CLSCTX.CLSCTX_RESERVED3) ContextMask.push("CLSCTX_RESERVED3");
    if ( (enumval & CLSCTX.CLSCTX_RESERVED4) == CLSCTX.CLSCTX_RESERVED4) ContextMask.push("CLSCTX_RESERVED4");
    if ( (enumval & CLSCTX.CLSCTX_NO_CODE_DOWNLOAD) == CLSCTX.CLSCTX_NO_CODE_DOWNLOAD) ContextMask.push("CLSCTX_NO_CODE_DOWNLOAD");
    if ( (enumval & CLSCTX.CLSCTX_RESERVED5) == CLSCTX.CLSCTX_RESERVED5) ContextMask.push("CLSCTX_RESERVED5");
    if ( (enumval & CLSCTX.CLSCTX_NO_CUSTOM_MARSHAL) == CLSCTX.CLSCTX_NO_CUSTOM_MARSHAL) ContextMask.push("CLSCTX_NO_CUSTOM_MARSHAL");
    if ( (enumval & CLSCTX.CLSCTX_ENABLE_CODE_DOWNLOAD) == CLSCTX.CLSCTX_ENABLE_CODE_DOWNLOAD) ContextMask.push("CLSCTX_ENABLE_CODE_DOWNLOAD");
    if ( (enumval & CLSCTX.CLSCTX_NO_FAILURE_LOG) == CLSCTX.CLSCTX_NO_FAILURE_LOG) ContextMask.push("CLSCTX_NO_FAILURE_LOG");
    if ( (enumval & CLSCTX.CLSCTX_DISABLE_AAA) == CLSCTX.CLSCTX_DISABLE_AAA) ContextMask.push("CLSCTX_DISABLE_AAA");
    if ( (enumval & CLSCTX.CLSCTX_ENABLE_AAA) == CLSCTX.CLSCTX_ENABLE_AAA) ContextMask.push("CLSCTX_ENABLE_AAA");
    if ( (enumval & CLSCTX.CLSCTX_FROM_DEFAULT_CONTEXT) == CLSCTX.CLSCTX_FROM_DEFAULT_CONTEXT) ContextMask.push("CLSCTX_FROM_DEFAULT_CONTEXT");
    if ( (enumval & CLSCTX.CLSCTX_ACTIVATE_32_BIT_SERVER) == CLSCTX.CLSCTX_ACTIVATE_32_BIT_SERVER) ContextMask.push("CLSCTX_ACTIVATE_32_BIT_SERVER");
    if ( (enumval & CLSCTX.CLSCTX_ACTIVATE_64_BIT_SERVER) == CLSCTX.CLSCTX_ACTIVATE_64_BIT_SERVER) ContextMask.push("CLSCTX_ACTIVATE_64_BIT_SERVER");
    
    // Create string result
    var StringResult = ContextMask.join("|");
    return StringResult;

}

// Call native Ole32!StringFromCLSID to resolve CLSID
function StringSidFromRclsid(rclsid) {
    // Heap alloc pointer sized mem
    var lplpsz = Memory.alloc(8)
    // Call function & read CLSID
    var CallResult = fStringFromCLSID(rclsid, lplpsz)
    if (CallResult == 0) {
        var CLSID = (lplpsz.readPointer()).readUtf16String();
        return CLSID;
    } else {
        return "StringFromCLSID failed!";
    }
}

// Hooks
//-----------------------
Interceptor.attach(pCoGet, {
	onEnter: function (args) {

        // Parse CLSID in memory
		var sCLSID = StringSidFromRclsid(args[0]);

        // Parse Context mask
        var sClsContext = GetClsContextMask(args[1]);

        // COM object is initialized on remote host?
        if (args[2].compare(0x0) == 0) {
            var pLocation = "Local COM invocation"
        } else {
            var pLocation = "Remote COM invocation"
        }

		send("[+] Called CoGetClassObject")
		send("    rclsid       : " + sCLSID)
		send("    dwClsContext : " + sClsContext)
		send("    pvReserved   : " + pLocation)
		send("    riid         : " + args[3])
		send("    *ppv         : " + args[4] + "\n")
	}
});