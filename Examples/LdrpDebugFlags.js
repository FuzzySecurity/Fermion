//------------------------------------------------------------------------------------//
// Leak and toggle ntdll!LdrpDebugFlags in memory to turn on ShowSnaps. Leak and hook //
// vDbgPrintExWithPrefixInternal & vDbgPrintExWithPrefixInternal->vsnprintf to print  //
// the ShowSnaps debug messages.                                                      //
//                                                                                    //
//                      !!Tested only on x64 Win10 1903!!                             //
//------------------------------------------------------------------------------------//

// pFunction
var pLdrLoadDll = Module.findExportByName('ntdll.dll', 'LdrLoadDll')

// Globals
var iDebugOffet;
var pLdrpDebugFlags;
var pDebugFarjump;
var iDebugFarJump;
var iDbgPrintOffset;
var pLdrpLogDbgPrint;
var ivDbgInternal;
var pvDbgPrintExWithPrefixInternal;
var pvsnprintf;

// Deubg vars
var prefix;
var suffix;
var pattern = /^\w+:\w+\s/i

// Leak LdrpLoadDll
send("[?] Leaking LdrpDebugFlags..");
send("[+] LdrLoadDll: " + pLdrLoadDll);

var typedByteArray = new Uint8Array(pLdrLoadDll.readByteArray(150));
for (var i=0;i<typedByteArray.length;i++) {
    //----------------------
    // f6051be4130009 test byte ptr [ntdll!LdrpDebugFlags (00007ffc`e0a5fab0)],9
    // 0f8515b90800   jne ntdll!LdrLoadDll+0x8b9a0 (00007ffc`e09acfb0)
    //----------------------
    if (typedByteArray[i] == 0xf6){
        if (typedByteArray[i+6] == 0x9){
            iDebugOffet = (pLdrLoadDll.add(i+2)).readU32();
            send("[+] Offset DbgFlags: " + iDebugOffet);
            pLdrpDebugFlags = pLdrLoadDll.add(i+iDebugOffet+7);
            send("[+] ntdll!LdrpDebugFlags: " + pLdrpDebugFlags);
            iDebugFarJump = ((pLdrLoadDll.add(i+7+2)).readU32() + i+7+6);
            send("[+] Debug far jump: " + iDebugFarJump);
            break;
        }
    }
}

// Leak LdrpLogDbgPrint
var pDebugFarJmp = pLdrLoadDll.add(iDebugFarJump);
send("[?] Leaking LdrpLogDbgPrint..");
send("[+] pDebugFarJmp: " + pDebugFarJmp);

var typedByteArray = new Uint8Array(pDebugFarJmp.readByteArray(50));
for (var i=0;i<typedByteArray.length;i++) {
    //----------------------
    // 488d0d26f50700 lea rcx,[ntdll!`string' (00007ffc`e0a2c500)]
    // e849150200     call ntdll!LdrpLogDbgPrint (00007ffc`e09ce528)
    //----------------------
    if (typedByteArray[i] == 0xe8){
        iDbgPrintOffset = (pDebugFarJmp.add(i+1)).readU32();
        send("[+] LdrpLogDbgPrint Offset: " + iDbgPrintOffset);
        pLdrpLogDbgPrint = pDebugFarJmp.add(i+iDbgPrintOffset+5);
        send("[+] ntdll!LdrpLogDbgPrint: " + pLdrpLogDbgPrint);
    }
}

// Leak vDbgPrintExWithPrefixInternal
send("[?] Leaking vDbgPrintExWithPrefixInternal..");
var typedByteArray = new Uint8Array(pLdrpLogDbgPrint.readByteArray(250));
for (var i=0;i<typedByteArray.length;i++) {
    //----------------------
    // 418d5055   lea edx,[r8+55h]
    // e88851f8ff call ntdll!vDbgPrintExWithPrefixInternal (00007ffc`e0953788)
    //----------------------
    if (typedByteArray[i] == 0xe8){
        if (typedByteArray[i-4] == 0x41){
            ivDbgInternal = (pLdrpLogDbgPrint.add(i+1)).readU32();
            send("[+] vDbgPrintExWithPrefixInternal Offset: " + ivDbgInternal);
            pvDbgPrintExWithPrefixInternal = pLdrpLogDbgPrint.add(i+ivDbgInternal+5-0x100000000);
            send("[+] ntdll!vDbgPrintExWithPrefixInternal: " + pvDbgPrintExWithPrefixInternal);
            break;
        }
    }
}

// Leak vDbgPrintExWithPrefixInternal->vsnprintf
send("[?] Leaking vDbgPrintExWithPrefixInternal->vsnprintf..");
var typedByteArray = new Uint8Array(pvDbgPrintExWithPrefixInternal.readByteArray(350));
for (var i=0;i<typedByteArray.length;i++) {
    //----------------------
    // 498bd4     mov rdx,r12
    // e8c0a00300 call ntdll!vsnprintf (00007ffc`e098d9a0)
    //----------------------
    if (typedByteArray[i] != 0x00){
        if (typedByteArray[i-1] == 0xd4){
            pvsnprintf = pvDbgPrintExWithPrefixInternal.add((pvDbgPrintExWithPrefixInternal.add(i+1)).readU32()+i+5);
            send("[+] vsnprintf: " + pvsnprintf);
            break;
        }
    }
}

// Rewrite flag in memory ==> 0x9
send("[?] Overwriting LdrpDebugFlags==0x9");
pLdrpDebugFlags.writeU32(9);

send("[?] Hooking..\n");
Interceptor.attach(pvDbgPrintExWithPrefixInternal, {
    onEnter: function (args) {
        if (suffix != null) {
            send(prefix + suffix);
            prefix = suffix = null;
        }
        prefix = args[0].readAnsiString();
    }
});

Interceptor.attach(pvsnprintf, {
    onEnter: function (args) {
        this.strPtr = args[0];
    },
    onLeave: function (retval) {
        if (!pattern.test((this.strPtr).readAnsiString())){
            suffix = ((this.strPtr).readAnsiString()).replace(/\n$/, "");
        }
    }
});