//-------------------------//
// Load library call chain //
//-------------------------//

// Native function pointers
var pLoadLibraryA = Module.findExportByName('Kernel32.dll','LoadLibraryA')
var pLoadLibraryW = Module.findExportByName('Kernel32.dll','LoadLibraryW')
var pLoadLibraryExA = Module.findExportByName('Kernel32.dll','LoadLibraryExA')
var pLoadLibraryExW = Module.findExportByName('Kernel32.dll','LoadLibraryExW')
var pLdrLoadDll = Module.findExportByName('ntdll.dll','LdrLoadDll')

// Enums
var Dll_dwFlags = {
    NONE : 0x0,
    DONT_RESOLVE_DLL_REFERENCES : 0x1,
    LOAD_IGNORE_CODE_AUTHZ_LEVEL : 0x10,
    LOAD_LIBRARY_AS_DATAFILE : 0x2,
    LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE : 0x40,
    LOAD_LIBRARY_AS_IMAGE_RESOURCE : 0x20,
    LOAD_LIBRARY_SEARCH_APPLICATION_DIR : 0x200,
    LOAD_LIBRARY_SEARCH_DEFAULT_DIRS : 0x1000,
    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR : 0x100,
    LOAD_LIBRARY_SEARCH_SYSTEM32 : 0x800,
    LOAD_LIBRARY_SEARCH_USER_DIRS : 0x400,
    LOAD_WITH_ALTERED_SEARCH_PATH : 0x8
}

// Helpers
function ParseDllFlags(FlagVal) {
    var BitMask = [];

    if (FlagVal == Dll_dwFlags.NONE) {
        BitMask.push("NONE");
    } else {
        if ((FlagVal & Dll_dwFlags.DONT_RESOLVE_DLL_REFERENCES) == Dll_dwFlags.DONT_RESOLVE_DLL_REFERENCES) BitMask.push("DONT_RESOLVE_DLL_REFERENCES");
        if ((FlagVal & Dll_dwFlags.LOAD_IGNORE_CODE_AUTHZ_LEVEL) == Dll_dwFlags.LOAD_IGNORE_CODE_AUTHZ_LEVEL) BitMask.push("LOAD_IGNORE_CODE_AUTHZ_LEVEL");
        if ((FlagVal & Dll_dwFlags.LOAD_LIBRARY_AS_DATAFILE) == Dll_dwFlags.LOAD_LIBRARY_AS_DATAFILE) BitMask.push("LOAD_LIBRARY_AS_DATAFILE");
        if ((FlagVal & Dll_dwFlags.LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE) == Dll_dwFlags.LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE) BitMask.push("LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE");
        if ((FlagVal & Dll_dwFlags.LOAD_LIBRARY_AS_IMAGE_RESOURCE) == Dll_dwFlags.LOAD_LIBRARY_AS_IMAGE_RESOURCE) BitMask.push("LOAD_LIBRARY_AS_IMAGE_RESOURCE");
        if ((FlagVal & Dll_dwFlags.LOAD_LIBRARY_SEARCH_APPLICATION_DIR) == Dll_dwFlags.LOAD_LIBRARY_SEARCH_APPLICATION_DIR) BitMask.push("LOAD_LIBRARY_SEARCH_APPLICATION_DIR");
        if ((FlagVal & Dll_dwFlags.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) == Dll_dwFlags.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) BitMask.push("LOAD_LIBRARY_SEARCH_DEFAULT_DIRS");
        if ((FlagVal & Dll_dwFlags.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR) == Dll_dwFlags.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR) BitMask.push("LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR");
        if ((FlagVal & Dll_dwFlags.LOAD_LIBRARY_SEARCH_SYSTEM32) == Dll_dwFlags.LOAD_LIBRARY_SEARCH_SYSTEM32) BitMask.push("LOAD_LIBRARY_SEARCH_SYSTEM32");
        if ((FlagVal & Dll_dwFlags.LOAD_LIBRARY_SEARCH_USER_DIRS) == Dll_dwFlags.LOAD_LIBRARY_SEARCH_USER_DIRS) BitMask.push("LOAD_LIBRARY_SEARCH_USER_DIRS");
        if ((FlagVal & Dll_dwFlags.LOAD_WITH_ALTERED_SEARCH_PATH) == Dll_dwFlags.LOAD_WITH_ALTERED_SEARCH_PATH) BitMask.push("LOAD_WITH_ALTERED_SEARCH_PATH");
    }

    if (BitMask.length == 0) {
        BitMask.push(FlagVal);
    }

    return BitMask.join("|");
}

// Hook
Interceptor.attach(pLoadLibraryA, {
	onEnter: function (args) {
		send("[+] Called LoadLibraryA")
        send("    |-> LPCSTR: " + args[0].readAnsiString() + "\n")
	}
});

Interceptor.attach(pLoadLibraryW, {
	onEnter: function (args) {
		send("[+] Called LoadLibraryW")
        send("    |-> LPCWSTR: " + args[0].readUtf16String() + "\n")
	}
});

Interceptor.attach(pLoadLibraryExA, {
	onEnter: function (args) {
        var FlagVals = ParseDllFlags(args[2])
		send("[+] Called LoadLibraryExA")
        send("    |-> LPCSTR  : " + args[0].readAnsiString())
        send("    |-> dwFlags : " + FlagVals)
	}
});

Interceptor.attach(pLoadLibraryExW, {
	onEnter: function (args) {
        var FlagVals = ParseDllFlags(args[2])
		send("[+] Called LoadLibraryExW")
        send("    |-> LPCWSTR : " + args[0].readUtf16String())
        send("    |-> dwFlags : " + FlagVals)
	}
});

Interceptor.attach(pLdrLoadDll, {
	onEnter: function (args) {
        // Store arg pointers to read in onLeave
        // The base address is only populated after the call
        this.NamePtr = args[2];
        this.BasePtr = args[3];
	},

    onLeave: function (retval) {
        send("[+] Called LdrLoadDll")

        //---------
        // Note here that the module name layout is as follows:
        // LdrLoadDll->[PUNICODE_STRING]Name
        //             |-> [UInt16]Len     => 2-bytes
        //             |-> [UInt16]MaxLen  => 2-bytes
        //             |-> [IntPtr]Buffer  => 4-bytes x86 / 8-bytes x64
        //---------
        // The trick though is that, for alignment, on x64 an
        // extra 4-bytes of padding is inserted after MaxLen.
        //---------
        var sName = (((this.NamePtr).add(8)).readPointer()).readUtf16String();
        var pBase = (this.BasePtr).readPointer()
        send("    |-> Module Name : " + sName)
        send("    |-> BaseAddress : " + pBase)
    }
});


