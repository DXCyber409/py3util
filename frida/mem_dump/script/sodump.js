/**
 * 设置字符串format函数
 * 例子: '{0}{1}.format(5,6)'
 */
String.prototype.format = function () {
    var values = arguments;
    return this.replace(/\{(\d+)\}/g, function (match, index) {
        if (values.length > index) {
            return values[index];
        } else {
            return "";
        }
    });
};

// function m_info(module) {
//   if (module == null)
//     return;

//   var name = module['name'];
//   var addr_start = parseInt(module['base'], 16);
//   var size = module['size'];
//   var addr_end = (addr_start + size);

//   var s_addr_start = addr_start.toString(16).toUpperCase();
//   var s_addr_end = addr_end.toString(16).toUpperCase();
//   console.log('name:{0}, addr_start:{1}, addr_end:{2}'.format(name, s_addr_start, s_addr_end));
// }

// console.log('Process.id:' + Process.id);
// var threads = Process.enumerateThreads();
// var modules = Process.enumerateModules();
// // for (var i = 0; i < modules.length; i ++) {
// //   console.log(JSON.stringify(modules[i])); // 1, "string", false
// // }

// // var module = Process.findModuleByName('libchromium_android_linker.so')
// // console.log(JSON.stringify(module));
// // var exports = module.enumerateImports();

// // var m_libc = Process.findModuleByName('libc.so');
// // console.log(JSON.stringify(m_libc));
// // var m_libart = Process.findModuleByName('libart.so');
// // console.log(JSON.stringify(m_libart));

// for (let module of Process.enumerateModules()) {
//     console.log(JSON.stringify(module));
// }

function sodump(module_name) {
    var module_file_name = 'lib{0}.so'.format(module_name);
    console.log(module_file_name);
    var libmodule = Process.findModuleByName(module_file_name);
    var module_base = libmodule['base'];
    var module_size = libmodule['size'];
    console.log(JSON.stringify(libmodule));
    Memory.protect(ptr(module_base), module_size, 'rwx');
    console.log('mprotect patch success.');
    var buffer = ptr(module_base).readByteArray(module_size);
    send('lib{0}_{1}'.format(module_name, module_base), buffer);
}
