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

rpc.exports = {
  sodump: function (name) {
      return sodump(name);
  },
  memdump1: function (addr_start, addr_end) {
    return memdump1(addr_start, addr_end);
  },
  memdump2: function (addr_start, size) {
    return memdump2(addr_start, size);
  },
  sodumpAll: function (tag) {
    return sodump_all(tag);
  },
};

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
  var payload = {
    "action": "sodump",
    "filename": 'lib{0}_{1}'.format(module_name, module_base),
  };
  send(JSON.stringify(payload), buffer);
  return true;
}

function memdump1(addr_start, addr_end) {
  var size = addr_end - addr_start;
  var hsize = size.toString(16);
  var haddr_start = addr_start.toString(16);

  Memory.protect(ptr(addr_start), size, 'rwx');
  console.log('{0}-{1}mprotect patch success.'.format(addr_start, addr_end));
  var buffer = ptr(addr_start).readByteArray(size);
  var payload = {
    "action": "memdump",
    "filename": 'memdump_{0}_{1}'.format(haddr_start, hsize),
  };
  send(JSON.stringify(payload), buffer);
  return true;
}

function memdump2(addr_start, size) {
  var hsize = size.toString(16);
  var haddr_start = addr_start.toString(16);

  Memory.protect(ptr(addr_start), size, 'rwx');
  console.log('{0}-{1}mprotect patch success.');
  var buffer = ptr(addr_start).readByteArray(size);
  var payload = {
    "action": "memdump",
    "filename": 'memdump_{0}_{1}'.format(haddr_start, hsize),
  };
  send(JSON.stringify(payload), buffer);
  return true;
}

function sodump_all(tag) {
  console.log(tag);
  var modules = Process.enumerateModules();
  for (var i=0; i<modules.length; i++) {
    var module = modules[i];
    if (module.path.indexOf(tag) !== -1 && module.path.indexOf(".so") !== -1) {
      // console.log(JSON.stringify(module));
      Memory.protect(ptr(module.base), module.size, 'rwx');
      console.log('name:{0} base:{1} size:{2} mprotect patch success.'.format(module.name, module.base, module.size));
      var payload = {
        "action": "sodumpAll",
        "filename": module.name + "." + module.base,
      };
      var buffer = ptr(module.base).readByteArray(module.size);
      send(JSON.stringify(payload), buffer);
    }
  }
}
