//---------------------------------------//
// Simple wrappers for Instruction.parse //
//---------------------------------------//

// Native function pointer
var pNtQuerySection = Module.findExportByName('ntdll.dll', 'NtQuerySection');

// Disassemble x instructions at NativePointer
//--------
function GetDisAsmPtr(nativePtr, instructionCount) {
    // Result array
    var instructionArr = [];

    // Loop
    for (var i=0; i<instructionCount; i++) {
        var dissAsm = Instruction.parse(nativePtr);
        instructionArr.push(dissAsm);
        nativePtr = dissAsm.next;
    }

    return instructionArr;
}

// Disassemble instructions from byte array
//--------
function GetDisAsmBytes(byteArray) {
    if (byteArray.length == 0 || byteArray.length == undefined) {
        send("[!] Invalid byte array..");
        return;
    } else {
        // Result array
        var instructionArr = [];

        // Get array length
        var arrLen = byteArray.length;

        // Whatever the array is we pad it with 20 null's
        // |-> we do this because the instructions may be incomplete
        for (var i=0; i<20; i++) {
            byteArray.push(0x0);
        }

        // Alloc & write array
        var arrPtr = Memory.alloc(byteArray.length);
        arrPtr.writeByteArray(byteArray);

        // Loop based on original length
        var count = 0;
        var offset = arrPtr;
        do {
            var dissAsm = Instruction.parse(offset);
            instructionArr.push(dissAsm);
            count += dissAsm.size;
            offset = dissAsm.next;
        } while (count<arrLen)

        return instructionArr;
    }
}

// Parse instructions detailed/simple
//--------
function ParseIntstructionArray(instArray, isDetailed) {
    if (instArray.length == 0 || instArray.length == undefined) {
        send("[!] Invalid instruction array..");
        return;
    } else {
        for (var i=0; i<instArray.length; i++) {
            if (isDetailed == true) {
                send("Address  : " + instArray[i].address);
                send("Size     : " + instArray[i].size);
                send("Mnemonic : " + instArray[i].mnemonic);
                send("Operands : " + instArray[i].opStr);
                send("RegRead  : " + (instArray[i].regsRead).join(", "));
                send("RegWrite : " + (instArray[i].regsWritten).join(", "));
                send("Groups   : " + (instArray[i].groups).join(", ") + "\n");
            } else {
                send(instArray[i].address + ": " + instArray[i].toString());
            }
        }
    }
}

// DisAsm program pointer
send("\n[?] Disassemble ntdll!NtQuerySection..");
ParseIntstructionArray(GetDisAsmPtr(pNtQuerySection, 5), false);

// DisAsm byte array
send("\n[?] Disassemble byte array detailed..");
var aBytes = [0xB8, 0x0A, 0x00, 0x00, 0x00, 0xF7, 0xF3];
ParseIntstructionArray(GetDisAsmBytes(aBytes), true);
