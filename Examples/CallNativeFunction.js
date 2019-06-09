//--------------------------//
// Calling Native Functions //
//--------------------------//

// Native function pointer
var pMessageBoxA = Module.findExportByName("User32.dll","MessageBoxA");

// Function prototype
var fMessageBox = new NativeFunction(
    pMessageBoxA,
    "int",
    [
        "pointer",
        "pointer", 
        "pointer", 
        "uint"
    ]
);

// Function parameters
var lpText = Memory.allocAnsiString("Hello from Frida!");
var lpCaption = Memory.allocAnsiString("b33f");

// Call function
send("[+] Calling MessageBoxA in remote proc..");
var CallResult = fMessageBox(ptr(0), lpText, lpCaption, 1);

// Print function return value
send("    |-> CallResult => " + CallResult);