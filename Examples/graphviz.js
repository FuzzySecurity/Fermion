//------------------------------------//
// GraphViz CALL tracing with Stalker //
// Just POC, code needs work!         //
//------------------------------------//

// Native function pointers
//-----------------------
var pFunctionPtr = Module.findExportByName('kernel32.dll', 'CreateFileW');

// Globals
//-----------------------
var modMap = new ModuleMap;
var isInitCall = true;
var callSites;
var previousNode;
var startNode;
var endNode;

// Boilerplate printer
//-----------------------
function printGraphVizHead() {
    var sHdr = `digraph G {
    ratio=fill;
    node[fontsize=24,style=filled,shape=rectangle];
    edge [style=dashed];

`;
    send(sHdr);
}

function printGraphVizFooter(start, end) {
    send("\n    \"" + start + "\" [shape=invhouse, color=green];");
    send("    \"" + end + "\" [shape=house, color=red];");
    send("}");
}

// Call site parser
//-----------------------
function parseCallSites(callSites) {
    if (callSites == undefined || callSites.length == 0) {
        return;
    } else {
        // print Hdr
        printGraphVizHead();

        // Set start node
        startNode = pFunctionPtr;

        // Loop call sites
        for (var i = 0; i < callSites.length; i++) {
            var oModuleFrom = modMap.find(ptr(callSites[i][1].toString()));
            var oModuleTo = modMap.find(ptr(callSites[i][2].toString()));
            if (oModuleFrom != null) {
                if ((oModuleFrom.name).toLowerCase().indexOf("frida") == -1) {
                    var pSymbolFrom = ptr(callSites[i][1].toString());
                    var sSymbolFrom = DebugSymbol.fromAddress(ptr(callSites[i][1].toString())).name;
                    var pSymbolTo = ptr(callSites[i][2].toString());
                    var sSymbolTo = DebugSymbol.fromAddress(ptr(callSites[i][1].toString())).name;
                    if (isInitCall) {
                        send("    \"" + pFunctionPtr + "\"->\"" + pSymbolFrom + "\\n" + oModuleFrom.name + "!" + sSymbolFrom + "\";");
                        send("    \"" + pSymbolFrom + "\\n" + oModuleFrom.name + "!" + sSymbolFrom + "\"->\"" + pSymbolTo + "\\n" + oModuleTo.name + "!" + sSymbolTo + "\";");
                        isInitCall = false;
                    } else {
                        send("    \"" + previousNode + "\"->\"" + pSymbolFrom + "\\n" + oModuleFrom.name + "!" + sSymbolFrom + "\"->\"" + pSymbolTo + "\\n" + oModuleTo.name + "!" + sSymbolTo + "\";");
                    }

                    // Save previous node
                    previousNode = pSymbolTo + "\\n" + oModuleTo.name + "!" + sSymbolTo;

                    // Update end node
                    endNode = pSymbolTo + "\\n" + oModuleTo.name + "!" + sSymbolTo;
                }
            }
        }

        // print Ftr
        printGraphVizFooter(startNode, endNode);
        isInitCall = true;
    }
}

// Hook & Stalk
//-----------------------
Interceptor.attach(pFunctionPtr, {
    onEnter: function (args) {
        send("\n[+] Calling function..");
        send("    |-> Tracing execution with stalker\n");

        var cTid = Process.getCurrentThreadId();
        Stalker.follow(cTid, {
            events: {call: true, ret: false},
            onReceive: function (events) {
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
            callSites = undefined;
        }
    }
});