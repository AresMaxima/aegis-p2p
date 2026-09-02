// Interception des symboles FFI exportés dans libaegis_core.so
const moduleName = "libaegis_core.so";

function hookAegis() {
    const baseAddr = Module.findBaseAddress(moduleName);
    if (!baseAddr) {
        console.log("[-] libaegis_core.so non chargé en mémoire.");
        return;
    }
    console.log("[+] Base address de libaegis_core.so : " + baseAddr);

    // 1. Interception de aegis_init_vault_path
    const initVaultPtr = Module.findExportByName(moduleName, "aegis_init_vault_path");
    if (initVaultPtr) {
        Interceptor.attach(initVaultPtr, {
            onEnter: function (args) {
                console.log("[*] FFI Call -> aegis_init_vault_path");
                console.log("    Path arg : " + Memory.readUtf8String(args[0]));
            },
            onLeave: function (retval) {
                console.log("    Return code : " + retval);
            }
        });
    }

    // 2. Monitoring du déclenchement PanicPurge (exit 137)
    const panicPurgePtr = Module.findExportByName(moduleName, "aegis_panic_purge");
    if (panicPurgePtr) {
        Interceptor.attach(panicPurgePtr, {
            onEnter: function (args) {
                console.log("[!] CRITIQUE -> aegis_panic_purge appelé ! Destruction RAM en cours...");
            }
        });
    }
}

setImmediate(hookAegis);