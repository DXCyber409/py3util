
console.log('Process.id:' + Process.id);

var modules = Process.enumerateModules();
for (var i = 0; i < modules.length; i ++) {
  var text = JSON.stringify(modules[i]);
  if (text.indexOf("com.android.bankabc") !== -1 && text.indexOf(".so") !== -1) {
    console.log(text); // 1, "string", false
  }
}

// var module = Process.findModuleByName('libchromium_android_linker.so')
// console.log(JSON.stringify(module));
// var exports = module.enumerateImports();

// var m_libc = Process.findModuleByName('libc.so');
// console.log(JSON.stringify(m_libc));
// var m_libart = Process.findModuleByName('libart.so');
// console.log(JSON.stringify(m_libart));

// for (let module of Process.enumerateModules()) {
//     console.log(JSON.stringify(module));
// }