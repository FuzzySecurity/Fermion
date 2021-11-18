
// Globals
//-----------------------
var modMap = new ModuleMap;
var isInitCall = true;
var callSites;
var previousNode;
var startNode;
var endNode;
let uniqueTrace = null;

// Boilerplate printer
//-----------------------
function printGraphVizHead() {
    var sHdr = `digraph Graph {
    ratio=fill;
    node[fontsize=24,style=filled,shape=rectangle];
    edge [style=dashed];

`;
    uniqueTrace = sHdr;
}

function printGraphVizFooter(start, end) {
    uniqueTrace += "\n    \"" + start + "\" [shape=invhouse, color=green];\n";
    uniqueTrace += "    \"" + end + "\" [shape=house, color=red];\n";
    uniqueTrace += "}";
}

// Call site parser
//-----------------------
function parseCallSites(callSites) {
    if (callSites == undefined || callSites.length == 0) {
        return;
    } else {
        // Null existing trace
        uniqueTrace = null;

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
                    var sSymbolTo = DebugSymbol.fromAddress(ptr(callSites[i][2].toString())).name;
                    if (isInitCall) {
                        uniqueTrace += "    \"" + pFunctionPtr + "\"->\"" + pSymbolFrom + "\\n" + oModuleFrom.name + "!" + sSymbolFrom + "\";\n";
                        uniqueTrace += "    \"" + pSymbolFrom + "\\n" + oModuleFrom.name + "!" + sSymbolFrom + "\"->\"" + pSymbolTo + "\\n" + oModuleTo.name + "!" + sSymbolTo + "\";\n";
                        isInitCall = false;
                    } else {
                        uniqueTrace += "    \"" + previousNode + "\"->\"" + pSymbolFrom + "\\n" + oModuleFrom.name + "!" + sSymbolFrom + "\"->\"" + pSymbolTo + "\\n" + oModuleTo.name + "!" + sSymbolTo + "\";\n";
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
        send(uniqueTrace);
        isInitCall = true;
    }
}

// Hook & Stalk
//-----------------------
Interceptor.attach(pFunctionPtr, {
    onEnter: function (args) {
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