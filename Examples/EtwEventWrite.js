//-----------------------//
// Hooking EtwEventWrite //
//-----------------------//

// Functions
//----------------------------------------------
var pEtwEventWrite = Module.findExportByName('ntdll.dll', 'EtwEventWrite')

// Helpers
//----------------------------------------------
function fParseEventDescriptor(pEventDescriptor) {
    // typedef struct _EVENT_DESCRIPTOR {
    //   USHORT    Id;
    //   UCHAR     Version;
    //   UCHAR     Channel;
    //   UCHAR     Level;
    //   UCHAR     Opcode;
    //   USHORT    Task;
    //   ULONGLONG Keyword;
    // } EVENT_DESCRIPTOR, *PEVENT_DESCRIPTOR;
    var eID = pEventDescriptor.readUShort();
    var eVersion = (pEventDescriptor.add(2)).readU8();
    var eChannel = (pEventDescriptor.add(3)).readU8();
    var eLevel = (pEventDescriptor.add(4)).readU8();
    var eOpcode = (pEventDescriptor.add(5)).readU8();
    var eTask = (pEventDescriptor.add(6)).readUShort();
    var eKeyword = (pEventDescriptor.add(8)).readU64();
    send("       |- Id      : " + eID);
    send("       |- Version : " + eVersion);
    send("       |- Channel : " + eChannel);
    send("       |- Level   : " + eLevel);
    send("       |- Opcode  : " + eOpcode);
    send("       |- Task    : " + eTask);
    send("       |- Keyword : " + eKeyword);
}

function fParseEventDataDescriptor(iCount, pEventDataDescriptor) {
    // typedef struct _EVENT_DATA_DESCRIPTOR {
    //   ULONGLONG Ptr;
    //   ULONG     Size;
    //   union {
    //     ULONG Reserved;
    //     struct {
    //       UCHAR  Type;
    //       UCHAR  Reserved1;
    //       USHORT Reserved2;
    //     } DUMMYSTRUCTNAME;
    //   } DUMMYUNIONNAME;
    // } EVENT_DATA_DESCRIPTOR, *PEVENT_DATA_DESCRIPTOR;
    for (var i = 0; i < iCount; i++) {
        var eDataPtr = pEventDataDescriptor.readPointer();
        var eDataSize = (pEventDataDescriptor.add(8)).readU32();
        var eDataReserved = (pEventDataDescriptor.add(12)).readU32();
        send("       |- EVENT_DATA_DESCRIPTOR");
        send("          |- pData     : " + eDataPtr);
        send("          |- iDataSize : " + eDataSize);
        if (eDataSize > 16) {
            send("          |- Data      : " + eDataPtr.readUtf16String(eDataSize));
        }
        pEventDataDescriptor = pEventDataDescriptor.add(16);
    }
}

// Hooks
//----------------------------------------------
Interceptor.attach(pEtwEventWrite, {
    onEnter: function (args) {
        send("\n[?] Called EtwEventWrite..");
        send("    |- hRegistration        : " + args[0]);
        send("    |- pEventDescriptor     : ");
        fParseEventDescriptor(args[1]);
        send("    |- UserDataCount        : " + args[2]);
        send("    |- pEventDataDescriptor : ");
        fParseEventDataDescriptor(args[2].toInt32(), args[3]);
    },
    onLeave: function (retval) {
    }
});