//-------------------------//
// Hooking DeviceIoControl //
//-------------------------//

// Native function pointers
//-----------------------
var pDeviceIoControl = Module.findExportByName('Kernel32.dll', 'DeviceIoControl')

// Hooks
//-----------------------
Interceptor.attach(pDeviceIoControl, {
	onEnter: function (args) {
        this.hDevice = args[0];
        this.dwIoControlCode = args[1];
        this.lpInBuffer = args[2];
        this.nInBufferSize = args[3];
        this.lpOutBuffer = args[4];
        this.nOutBufferSize = args[5];
        this.lpBytesReturned = args[6];
        this.lpOverlapped = args[7];
	},
	onLeave: function (retval) {
        send("\n[+] DeviceIoControl Success == " + ((retval.toInt32() > 0) ? "true":"false"));
        send("    |-> hDevice         : " + this.hDevice);
        send("    |-> dwIoControlCode : " + this.dwIoControlCode);
        send("    |-> lpInBuffer      : " + this.lpInBuffer);
        send("    |-> nInBufferSize   : " + this.nInBufferSize);
        send("    |-> lpOutBuffer     : " + this.nOutBufferSize);
        send("    |-> lpBytesReturned : " + this.lpBytesReturned);
        send("    |-> lpOverlapped    : " + this.lpOverlapped);

        // If buff in/out, hexdump
        if (parseInt(this.nInBufferSize) > 0) {
            send("    |-> InBuffer        :\n" + hexdump(this.lpInBuffer, {length:parseInt(this.nInBufferSize)}));
        }
        
        if (parseInt(this.nOutBufferSize) > 0) {
            send("    |-> OutBuffer      :\n" + hexdump(this.lpInBuffer, {length:parseInt(this.nOutBufferSize)}));
        }
    }
});