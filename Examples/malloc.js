//--------//
// Malloc //
//--------//

var pMalloc = Module.findExportByName(null, "malloc");

Interceptor.attach(pMalloc, {
    onEnter: function (args) {
        send("\n[+] Called malloc");
        send("    |_ Len     : " + args[0]);
        this.mallocLen = args[0];
    },

    onLeave: function (retval) {
        if (retval.toInt32() != 0) {
            send("    |_ Success : true");
            send("    |_ Dump    : \n" + hexdump(retval, {length:parseInt(this.mallocLen)}));
        } else {
            send("    |_ Success : false");
        }
    }
});