//----------------------------------//
// NtDeviceIoControlFile: send&recv //
//----------------------------------//

// API Def
// https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntdeviceiocontrolfile
//---------------
// __kernel_entry NTSTATUS NtDeviceIoControlFile(
//   IN HANDLE            FileHandle,
//   IN HANDLE            Event,
//   IN PIO_APC_ROUTINE   ApcRoutine,
//   IN PVOID             ApcContext,
//   OUT PIO_STATUS_BLOCK IoStatusBlock,
//   IN ULONG             IoControlCode,
//   IN PVOID             InputBuffer,
//   IN ULONG             InputBufferLength,
//   OUT PVOID            OutputBuffer,
//   IN ULONG             OutputBufferLength
// );
//---------------
var pNtDeviceIoControlFile = Module.findExportByName("ntdll.dll", "NtDeviceIoControlFile")

// Global
var iOffset;

// Check arch for offset
if (Process.arch == "x64") {
    iOffset = 0x8;
} else {
    iOffset = 0x4;
}

Interceptor.attach(pNtDeviceIoControlFile, {
    onEnter: function (args) {
        // IOCTL_AFD_RECV - 0x12017
        // IOCTL_AFD_SEND - 0x1201F
        this.IOCTL = args[5];
        if (args[5].compare(0x12017) == 0 || args[5].compare(0x1201F) == 0) {
            if (args[5].compare(0x12017) == 0) {
                send("IOCTL: IOCTL_AFD_RECV");
            } else {
                send("IOCTL: IOCTL_AFD_SEND");
            }
            // Store data ptr
            this.InputBuffer = args[6];
        }
    },

    onLeave: function (retval) {
        if (this.IOCTL == 0x12017 || this.IOCTL == 0x1201F) {
            var iLength = (this.InputBuffer.readPointer()).readU32();
            var pBuffer = ((this.InputBuffer.readPointer()).add(iOffset)).readPointer();
            send("Alloc Length: " + iLength);
            send("Data: \n" + hexdump(pBuffer, {length:iLength}));
        }
    }
});