//----------------------------------------//
// Tracing CALL instructions with Stalker //
//----------------------------------------//

// Native function pointers
//-----------------------
var pCreateFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');

// Globals
//-----------------------
var modMap = new ModuleMap;
var callSites;

// Call site parser
//-----------------------
function parseCallSites(callSites) {
    if (callSites == undefined || callSites.length == 0) {
        return;
    } else {
        for (var i = 0; i < callSites.length; i++) {
            var oModuleFrom = modMap.find(ptr(callSites[i][1].toString()));
            var oModuleTo = modMap.find(ptr(callSites[i][2].toString()));
            if (oModuleFrom != null) {
                if ((oModuleFrom.name).toLowerCase().indexOf("frida") == -1) {
                    var pSymbolFrom = ptr(callSites[i][1].toString());
                    var sSymbolFrom = DebugSymbol.fromAddress(ptr(callSites[i][1].toString())).name;
                    var pSymbolTo = ptr(callSites[i][2].toString());
                    var sSymbolTo = DebugSymbol.fromAddress(ptr(callSites[i][1].toString())).name;
                    send("        + FROM : " + pSymbolFrom + " @ " + oModuleFrom.name + "!" + sSymbolFrom);
                    send("        |_ TO  : " + pSymbolTo + " @ " + oModuleTo.name + "!" + sSymbolTo);
                }
            }
        }
    }
}

// Hook & Stalk
//-----------------------
Interceptor.attach(pCreateFileW, {
    onEnter: function (args) {
        send("\n[+] Calling CreateFileW");
        send("    |-> lpFileName : " + args[0].readUtf16String());
        send("    |-> Tracing execution with stalker...");

        // Init Stalker
        var cTid = Process.getCurrentThreadId();
        Stalker.follow(cTid, {
            events: {call: true},
            onReceive: function (events) {
                // Struct
                // https://github.com/frida/frida-gum/blob/7d058cacd6c1d29860b27a8654841bcf2348ee01/gum/gumevent.h#L41
                //----
                callSites = Stalker.parse(events);
            },
        });
    },
    onLeave: function (retval) {
        Stalker.flush();
        Stalker.unfollow();
        Stalker.garbageCollect();
        if (callSites == undefined) {
            return;
        } else {
            parseCallSites(callSites);
        }
    }
});