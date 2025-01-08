/*
Invoke

frida -U -p $(frida-ps -Uai | grep -i "1.1.1" | awk '{print $1}') -l warp_hook.js --debug

*/

function hookBoringSSLByPattern(module) {
    var moduleBase = module.base;
    var moduleSize = module.size;


    console.log("Module Base Address: " + moduleBase);
    console.log("Module Size: " + moduleSize);

    // First pattern to try
    var arch = Process.arch;
    console.log("[*] Start hooking on arch: "+arch);

    
    var patter_log_secret = "FF 43 02 D1 FD 7B 05 A9 F8 5F 06 A9 F6 57 07 A9 F4 4F 08 A9 FD 43 01 91 58 D0 3B D5 08 17 40 F9 A8 83 1F F8 08 34 40 F9 08 11 41 F9 E8 0D 00 B4";

    hook_log_secret_by_pattern(moduleBase, moduleSize, patter_log_secret, "ssl_log_secret()"); 
}

function get_page_infos(address){
    var targetAddress = ptr(address);
    console.log("Analyzing address: "+address);

    // Use Process.enumerateRanges to find memory page information
    var ranges = Process.enumerateRanges({
        protection: '---', // Match all pages
        coalesce: false    // Don't merge contiguous pages
    });

    for (var i = 0; i < ranges.length; i++) {
        var range = ranges[i];
        if (range.base.compare(targetAddress) <= 0 &&
            targetAddress.compare(range.base.add(range.size)) < 0) {
            console.log("Page Info:");
            console.log("  Base Address: " + range.base);
            console.log("  Size: " + range.size);
            console.log("  Protection: " + range.protection);
            console.log("  File Path: " + range.file ? range.file.path : "Anonymous");
            break;
        }
    }
}


function hook_log_secret_by_pattern(moduleBase, moduleSize, pattern, pattern_name){

    Memory.scan(moduleBase, moduleSize, pattern, {
                    onMatch: function(address, size) {
                        console.log("Pattern found at ("+pattern_name+"): " + address);
                        get_page_infos(address);
                        
                        // Hook the function using Interceptor
                        Interceptor.attach(address, {
                            onEnter: function(args) {
                                


                                 console.log("[*] successfully hooked ssl_log_secret()");
                                



                            },
                            onLeave: function(retval) {
                                console.log("[*] successfully hooked ssl_log_secret() on_leave");
                            }
                        });
                    }
                });
}



function hookDynamicLinker() {
    var dlopenAddr = Module.findExportByName("libdl.so", "dlopen");
    var androidDlopenExtAddr = Module.findExportByName("libdl.so", "android_dlopen_ext");

    function processLibraryLoad(libraryName) {
        if (libraryName.includes("libnativetunnel.so")) {
            console.log("[Dynamic Load] libnativetunnel.so loaded dynamically.");
            var module = Process.getModuleByName("libnativetunnel.so");
            if (module !== null) {
                hookBoringSSLByPattern(module);
            } else {
                console.log("[Dynamic Load] Failed to retrieve libnativetunnel.so module.");
            }
        }
    }

    if (dlopenAddr) {
        console.log("Hooking dlopen");
        Interceptor.attach(dlopenAddr, {
            onEnter: function (args) {
                this.libraryName = Memory.readCString(args[0]);
                console.log("[dlopen] Loading library: " + this.libraryName);
            },
            onLeave: function (retval) {
                if (this.libraryName) {
                    processLibraryLoad(this.libraryName);
                }
            }
        });
    } else {
        console.log("dlopen not found in libdl.so");
    }

    if (androidDlopenExtAddr) {
        console.log("Hooking android_dlopen_ext");
        Interceptor.attach(androidDlopenExtAddr, {
            onEnter: function (args) {
                this.libraryName = Memory.readCString(args[0]);
                console.log("[android_dlopen_ext] Loading library: " + this.libraryName);
            },
            onLeave: function (retval) {
                if (this.libraryName) {
                    processLibraryLoad(this.libraryName);
                }
            }
        });
    } else {
        console.log("android_dlopen_ext not found in libdl.so");
    }
} 

// Find the BoringSSL module
function findBoringSSLModule() {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var name = modules[i].name;
        if (name.startsWith("libnativetunnel.so") ) {
            console.log("Found BoringSSL Module in: " + name);
            return modules[i];
        }
    }
    console.log("BoringSSL module not found.");
    return null;
}


function main() {
    var module = findBoringSSLModule();
    if (module !== null) {
        hookBoringSSLByPattern(module);
    }
    hookDynamicLinker();
}


main();