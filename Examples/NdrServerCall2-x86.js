// Native pointer
//=====
var pNdrServerCall2 = Module.getExportByName("rpcrt4.dll", "NdrServerCall2");

// Print helper
//=====
function buf2hex(buffer) { // buffer is an ArrayBuffer
  return [...new Uint8Array(buffer)]
      .map(x => x.toString(16).padStart(2, '0'))
      .join('');
}

function convertFromRpcInterfaceInformation(pRpcInterfaceInformation, functionIndex) {
    var RpcInterfaceInformation = new NativePointer(pRpcInterfaceInformation);
    var pMIDL_SERVER_INFO = RpcInterfaceInformation.add(0x3c).readPointer();
    var pDispatchTable = pMIDL_SERVER_INFO.add(0x4).readPointer();

    // Get pointer from table
    var pFunction = pDispatchTable.add(4*functionIndex).readPointer();

    // Get symbol output
    var oDebug = DebugSymbol.fromAddress(pFunction);
    return oDebug.moduleName + "!" + oDebug.name;
}

function rpcDetail(pRPC_MESSAGE) {
    var RPC_MESSAGE = new NativePointer(pRPC_MESSAGE);
    var structRPC_MESSAGE = `
          _RPC_MESSAGE {
              Handle                   ${RPC_MESSAGE.readPointer()}
              DataRepresentation       ${RPC_MESSAGE.add(0x4).readU32()}
|-----------  *Buffer                  ${RPC_MESSAGE.add(0x8).readPointer()}
|             BufferLength             ${RPC_MESSAGE.add(0xc).readU32()}
|             ProcNum                  ${RPC_MESSAGE.add(0x10).readU32()}
|  |--------  TransferSyntax           ${RPC_MESSAGE.add(0x14).readPointer()}
|  |          *RpcInterfaceInformation ${RPC_MESSAGE.add(0x18).readPointer()}
|  |          *ReservedForRuntime      ${RPC_MESSAGE.add(0x1c).readPointer()}
|  |          *ManagerEpv              ${RPC_MESSAGE.add(0x20).readPointer()}
|  |          *ImportContext           ${RPC_MESSAGE.add(0x24).readPointer()}
|  |          RpcFlags                 ${RPC_MESSAGE.add(0x28).readU32()}
|  |      }
|  |     
|  |--->  RPC_SYNTAX_IDENTIFIER {
|             SyntaxGUID               ${buf2hex(RPC_MESSAGE.add(0x14).readPointer().readByteArray(16))}
|             MajorVersion             ${RPC_MESSAGE.add(0x14).readPointer().add(0x10).readU8()}
|             MinorVersion             ${RPC_MESSAGE.add(0x14).readPointer().add(0x12).readU8()}
|         }
|
|------> RPC_ARGUMENT_BUFFER:
${hexdump(RPC_MESSAGE.add(0x8).readPointer(), {length: RPC_MESSAGE.add(0xc).readU32()})}

[?] RPC Server routine
    |_ Index    : ${RPC_MESSAGE.add(0x10).readU32()}
    |_ Function : ${convertFromRpcInterfaceInformation(RPC_MESSAGE.add(0x18).readPointer(), RPC_MESSAGE.add(0x10).readU32())}
       |_ (0x18) RPC_MESSAGE.RpcInterfaceInformation
          |_ (0x3c) RPC_SERVER_INTERFACE.InterpreterInfo
             |_ (0x4) MIDL_SERVER_INFO.DispatchTable[${RPC_MESSAGE.add(0x10).readU32()}]
`;
    send(structRPC_MESSAGE);
}

// Hook NdrServerCall2
//=====
Interceptor.attach(pNdrServerCall2, {
    onEnter(args) {
        send("[>] Called rpcrt4!NdrServerCall2");
        rpcDetail(args[0]);
    }
});