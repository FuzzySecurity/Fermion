//----------------------------------//
// NtDeviceIoControlFile: send&recv //
//----------------------------------//

// API Def
//----------------------------------------------
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
//----------------------------------------------
// More details related to Send & Recv can be found here:
// => https://doxygen.reactos.org/de/d28/sndrcv_8c.html
var pNtDeviceIoControlFile = Module.findExportByName("ntdll.dll", "NtDeviceIoControlFile")

// Global
//----------------------------------------------
var iOffset;

// Check arch for offset
if (Process.arch == "x64") {
    iOffset = 0x8;
} else {
    iOffset = 0x4;
}

// Enum's
//----------------------------------------------
var IOCTL_AFD = {
    RECV: 0x12017, // IOCTL_AFD_RECV - 0x12017
    SEND: 0x1201F  // IOCTL_AFD_SEND - 0x1201F
}

var TDI_RECEIVE = {
    TDI_RECEIVE_BROADCAST: 0x00000004,
    TDI_RECEIVE_MULTICAST: 0x00000008,
    TDI_RECEIVE_PARTIAL: 0x00000010,
    TDI_RECEIVE_NORMAL: 0x00000020,
    TDI_RECEIVE_EXPEDITED: 0x00000040,
    TDI_RECEIVE_PEEK: 0x00000080,
    TDI_RECEIVE_NO_RESPONSE_EXP: 0x00000100,
    TDI_RECEIVE_COPY_LOOKAHEAD: 0x00000200,
    TDI_RECEIVE_ENTIRE_MESSAGE: 0x00000400,
    TDI_RECEIVE_AT_DISPATCH_LEVEL: 0x00000800,
    TDI_RECEIVE_CONTROL_INFO: 0x00001000
}

var TDI_SEND = {
    TDI_SEND_NORMAL: 0x0,
    TDI_SEND_EXPEDITED: 0x0020,
    TDI_SEND_PARTIAL: 0x0040,
    TDI_SEND_NO_RESPONSE_EXPECTED: 0x0080,
    TDI_SEND_NON_BLOCKING: 0x0100,
    TDI_SEND_AND_DISCONNECT: 0x0200
}

var AFD_SEND_RECV = {
    AFD_SKIP_FIO: 0x1,
    AFD_OVERLAPPED: 0x2,
    AFD_IMMEDIATE: 0x4
}

// Helpers
//----------------------------------------------
function GetTdiRecvMask(val) {
    var Mask = [];

    if ((val & TDI_RECEIVE.TDI_RECEIVE_BROADCAST) == TDI_RECEIVE.TDI_RECEIVE_BROADCAST) Mask.push("TDI_RECEIVE_BROADCAST");
    if ((val & TDI_RECEIVE.TDI_RECEIVE_MULTICAST) == TDI_RECEIVE.TDI_RECEIVE_MULTICAST) Mask.push("TDI_RECEIVE_MULTICAST");
    if ((val & TDI_RECEIVE.TDI_RECEIVE_PARTIAL) == TDI_RECEIVE.TDI_RECEIVE_PARTIAL) Mask.push("TDI_RECEIVE_PARTIAL");
    if ((val & TDI_RECEIVE.TDI_RECEIVE_NORMAL) == TDI_RECEIVE.TDI_RECEIVE_NORMAL) Mask.push("TDI_RECEIVE_NORMAL");
    if ((val & TDI_RECEIVE.TDI_RECEIVE_EXPEDITED) == TDI_RECEIVE.TDI_RECEIVE_EXPEDITED) Mask.push("TDI_RECEIVE_EXPEDITED");
    if ((val & TDI_RECEIVE.TDI_RECEIVE_PEEK) == TDI_RECEIVE.TDI_RECEIVE_PEEK) Mask.push("TDI_RECEIVE_PEEK");
    if ((val & TDI_RECEIVE.TDI_RECEIVE_NO_RESPONSE_EXP) == TDI_RECEIVE.TDI_RECEIVE_NO_RESPONSE_EXP) Mask.push("TDI_RECEIVE_NO_RESPONSE_EXP");
    if ((val & TDI_RECEIVE.TDI_RECEIVE_COPY_LOOKAHEAD) == TDI_RECEIVE.TDI_RECEIVE_COPY_LOOKAHEAD) Mask.push("TDI_RECEIVE_COPY_LOOKAHEAD");
    if ((val & TDI_RECEIVE.TDI_RECEIVE_ENTIRE_MESSAGE) == TDI_RECEIVE.TDI_RECEIVE_ENTIRE_MESSAGE) Mask.push("TDI_RECEIVE_ENTIRE_MESSAGE");
    if ((val & TDI_RECEIVE.TDI_RECEIVE_AT_DISPATCH_LEVEL) == TDI_RECEIVE.TDI_RECEIVE_AT_DISPATCH_LEVEL) Mask.push("TDI_RECEIVE_AT_DISPATCH_LEVEL");
    if ((val & TDI_RECEIVE.TDI_RECEIVE_CONTROL_INFO) == TDI_RECEIVE.TDI_RECEIVE_CONTROL_INFO) Mask.push("TDI_RECEIVE_CONTROL_INFO");

    // Return result
    if (Mask.length == 0) {
        return val;
    } else {
        return Mask.join("|");
    }
}

function GetTdiSendMask(val) {
    var Mask = [];

    if ((val & TDI_SEND.TDI_SEND_NORMAL) == TDI_SEND.TDI_SEND_NORMAL) Mask.push("TDI_SEND_NORMAL");
    if ((val & TDI_SEND.TDI_SEND_EXPEDITED) == TDI_SEND.TDI_SEND_EXPEDITED) Mask.push("TDI_SEND_EXPEDITED");
    if ((val & TDI_SEND.TDI_SEND_PARTIAL) == TDI_SEND.TDI_SEND_PARTIAL) Mask.push("TDI_SEND_PARTIAL");
    if ((val & TDI_SEND.TDI_SEND_NO_RESPONSE_EXPECTED) == TDI_SEND.TDI_SEND_NO_RESPONSE_EXPECTED) Mask.push("TDI_SEND_NO_RESPONSE_EXPECTED");
    if ((val & TDI_SEND.TDI_SEND_NON_BLOCKING) == TDI_SEND.TDI_SEND_NON_BLOCKING) Mask.push("TDI_SEND_NON_BLOCKING");
    if ((val & TDI_SEND.TDI_SEND_AND_DISCONNECT) == TDI_SEND.TDI_SEND_AND_DISCONNECT) Mask.push("TDI_SEND_AND_DISCONNECT");

    // Return result
    if (Mask.length == 0) {
        return val;
    } else {
        return Mask.join("|");
    }
}

function GetAfdMask(val) {
    var Mask = [];

    if ((val & AFD_SEND_RECV.AFD_SKIP_FIO) == AFD_SEND_RECV.AFD_SKIP_FIO) Mask.push("AFD_SKIP_FIO");
    if ((val & AFD_SEND_RECV.AFD_OVERLAPPED) == AFD_SEND_RECV.AFD_OVERLAPPED) Mask.push("AFD_OVERLAPPED");
    if ((val & AFD_SEND_RECV.AFD_IMMEDIATE) == AFD_SEND_RECV.AFD_IMMEDIATE) Mask.push("AFD_IMMEDIATE");

    // Return result
    if (Mask.length == 0) {
        return val;
    } else {
        return Mask.join("|");
    }
}

// Hooks
//----------------------------------------------
Interceptor.attach(pNtDeviceIoControlFile, {
    onEnter: function (args) {
        this.IOCTL = args[5];
        if (this.IOCTL == IOCTL_AFD.RECV || this.IOCTL == IOCTL_AFD.SEND) {
            // Store ptr's
            this.IoStatusBlock = args[4];
            this.InputBuffer = args[6];
        }
    },

    onLeave: function (retval) {
        if (this.IOCTL == IOCTL_AFD.RECV || this.IOCTL == IOCTL_AFD.SEND) {

            // Read IO_STATUS post call
            var iIOStatus = (this.IoStatusBlock).readU32();
            if (iIOStatus == 0) {
                iIOStatus = "STATUS_SUCCESS";
            }

            // Read PAFD_WSABUF
            var iLength = (this.InputBuffer.readPointer()).readU32();
            var pBuffer = ((this.InputBuffer.readPointer()).add(iOffset)).readPointer();

            // Read BufferCount
            var iBufferCount = ((this.InputBuffer).add(iOffset)).readU32();

            // Read AfdFlags
            var iAfdFlags = ((this.InputBuffer).add(iOffset + 4)).readU32();
            iAfdFlags = GetAfdMask(iAfdFlags);

            // Read TdiFlags
            var iTdiFlags = ((this.InputBuffer).add(iOffset + 8)).readU32();

            if (this.IOCTL == IOCTL_AFD.RECV) {
                send("\n[?] Type : IOCTL_AFD_RECV");
                // typedef struct _AFD_RECV_INFO {
                //     PAFD_WSABUF			BufferArray; -> [UINT len, PCHAR buf]
                //     ULONG				BufferCount;
                //     ULONG				AfdFlags;
                //     ULONG				TdiFlags;
                // } AFD_RECV_INFO , *PAFD_RECV_INFO ;

                iTdiFlags = GetTdiRecvMask(iTdiFlags);
            } else {
                send("\n[?] Type : IOCTL_AFD_SEND");
                // typedef struct _AFD_SEND_INFO {
                //     PAFD_WSABUF			BufferArray; -> [UINT len, PCHAR buf]
                //     ULONG				BufferCount;
                //     ULONG				AfdFlags;
                //     ULONG				TdiFlags;
                // } AFD_RECV_INFO , *PAFD_RECV_INFO ;

                iTdiFlags = GetTdiSendMask(iTdiFlags);
            }

            // Print
            send("[+] IO Status : " + iIOStatus);
            send("[+] Buff Count : " + iBufferCount);
            send("[+] AfdFlags : " + iAfdFlags);
            send("[+] TdiFlags : " + iTdiFlags);
            send("[+] Data Len : " + iLength);
            send("[+] Data :\n" + hexdump(pBuffer, {length:iLength}));
        }
    }
});