
//refs: https://github.com/Simp1er/MobileSec/blob/master/hook_constructors.js
// @ts-ignore
function waitForLoadLibraryNativeV2(libSoName,callback) {
    if (Process.pointerSize == 4) {
        var linker = Process.findModuleByName("linker");
    } else {
        var linker = Process.findModuleByName("linker64");
    }

    var addr_call_function =null;
    var addr_g_ld_debug_verbosity = null;
    var addr_async_safe_format_log = null;
    if (linker) {
        var symbols = linker.enumerateSymbols();
        for (var i = 0; i < symbols.length; i++) {
            var name = symbols[i].name;
            if (name.indexOf("call_function") >= 0){
                addr_call_function = symbols[i].address;
            }
            else if(name.indexOf("g_ld_debug_verbosity") >=0){
                addr_g_ld_debug_verbosity = symbols[i].address;

                // @ts-ignore
                ptr(addr_g_ld_debug_verbosity).writeInt(2);

            } else if(name.indexOf("async_safe_format_log") >=0 && name.indexOf('va_list') < 0){

                addr_async_safe_format_log = symbols[i].address;

            }

        }
    }
    if(addr_async_safe_format_log){
        Interceptor.attach(addr_async_safe_format_log,{
            onEnter: function(args){
                this.log_level  = args[0];
                // @ts-ignore
                this.tag = ptr(args[1]).readCString()
                // @ts-ignore
                this.fmt = ptr(args[2]).readCString()
                if(this.fmt.indexOf("c-tor") >= 0 && this.fmt.indexOf('Done') < 0){
                    // @ts-ignore
                    this.function_type = ptr(args[3]).readCString(), // func_type
                        // @ts-ignore
                        this.so_path = ptr(args[5]).readCString();
                    var strs: any[]; //定义一数组
                    strs = this.so_path.split("/"); //字符分割
                    this.so_name = strs.pop();
                    console.log("find so: ",this.so_name);
                    if(this.so_name==libSoName){
                        if(callback!=null)callback();
                    }
                    // @ts-ignore
                    this.func_offset  = ptr(args[4]).sub(Module.findBaseAddress(this.so_name))
                    console.log("func_type:", this.function_type,
                        '\nso_name:',this.so_name,
                        '\nso_path:',this.so_path,
                        '\nfunc_offset:',this.func_offset
                    );
                }
            },
            onLeave: function(retval){

            }
        })
        console.log("hook linker success");
    }
}
// @ts-ignore
function waitForLoadLibraryNative(libName,callback){
    // @ts-ignore
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function(args) {
            var pathptr = args[0];
            if (pathptr !== undefined && pathptr != null) {
                // @ts-ignore
                var path = ptr(pathptr).readCString();
                // @ts-ignore
                if (path.indexOf(libName) >= 0) {
                    this.findedLib = true;
                }
            }
        },
        onLeave: function(retval) {
            if (this.findedLib) {
                if(callback){
                    callback();
                    callback=null;
                }
            }
        }
    })

    // @ts-ignore
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function(args) {
            var pathptr = args[0];
            if (pathptr !== undefined && pathptr != null) {
                // @ts-ignore
                var path = ptr(pathptr).readCString();
                // @ts-ignore
                if (path.indexOf(libName) >= 0) {
                    this.findedLib = true;
                }
            }
        },
        onLeave: function(retval) {
            if (this.findedLib) {
                if(callback){
                    callback();
                    callback=null;
                }
            }
        }
    });
}

//refs:https://github.com/CreditTone/hooker/blob/master/js/dump_so.js
// @ts-ignore
function dump_so(so_name) {
    if (Java.available) {
        var libso = Process.findModuleByName(so_name);
        if(libso==null){
            waitForLoadLibraryNativeV2(so_name,function (){
                dump_so0(so_name)
            })
            waitForLoadLibraryNative(so_name,function (){
                dump_so0(so_name)
            })
        }else {
            dump_so0(so_name);
        }

    }else {
        console.log("java not available");
    }
}

// @ts-ignore
function dump_so0(so_name){
    Java.perform(function () {
        var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
        var dir = currentApplication.getApplicationContext().getFilesDir().getPath();
        var libso = Process.getModuleByName(so_name);
        console.log("[name]:", libso.name);
        console.log("[base]:", libso.base);
        console.log("[size]:", ptr(libso.size));
        console.log("[path]:", libso.path);
        var file_path = dir + "/" + libso.name + "_" + libso.base + "_" + ptr(libso.size) + ".so";
        var file_handle = new File(file_path, "wb");
        if (file_handle) {
            // @ts-ignore
            Memory.protect(ptr(libso.base), libso.size, 'rwx');
            // @ts-ignore
            var libso_buffer = ptr(libso.base).readByteArray(libso.size);
            // @ts-ignore
            file_handle.write(libso_buffer);
            file_handle.flush();
            file_handle.close();
            console.log("[dump]:", file_path);
        }
    });
}

dump_so("libxxxxxxxxx.so");
