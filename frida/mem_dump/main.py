import sys
import os
import time
import frida
import threading
import json

def so_fix(filename: str):
    pwd = os.path.dirname(__file__)

    def convert1(filename, target):
        libpath = os.path.join(pwd, "correctDump.exe")
        os.system("%s %s %s" % (libpath, filename, target))
    def convert2(filename, target):
        libpath = os.path.join(pwd, "correctDump2.exe")
        os.system("%s %s %s" % (libpath, filename, target))
    def convert3(filename, target):
        libpath = os.path.join(pwd, "rebuild_section.exe")
        os.system("%s %s %s" % (libpath, filename, target))

    filename1 = "%s.fix1.so" % filename
    filename2 = "%s.fix2.so" % filename
    filename3 = "%s.fix3.so" % filename
    threading.Thread(target=convert1, args=(filename, filename1), daemon=True).start()
    threading.Thread(target=convert2, args=(filename, filename2), daemon=True).start()
    threading.Thread(target=convert3, args=(filename1, filename3), daemon=True).start()

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
        payload = json.loads(message['payload'])
        # handle sodump
        if (payload['action'] == 'sodump' and data is not None):
            filename = 'dump/%s' % payload['filename']
            with open(filename, mode='wb') as f:
                f.write(data)
            so_fix(filename)
            print('[+]Dump %s ok' % filename)
        # handle memdump
        if (payload['action'] == 'memdump' and data is not None):
            filename = 'dump/%s' % payload['filename']
            with open(filename, mode='wb') as f:
                f.write(data)
            print('[+]Dump %s ok' % filename)
            
    elif message['type'] == 'error':
        print(message['stack'])

# 从usb设备连接frida-server，参数0表示不限等待时间，没有这个参数容易出现找不到设备
# device = frida.get_usb_device(0)

# 从TCP连接frida-server，指定IP和端口
device = frida.get_device_manager().add_remote_device("192.168.31.176:8002")

# 以spawn方式启动app并在最早时机阻塞，后续可通过attach后resume恢复app执行流程
# pid = device.spawn(["test"])
# session = device.attach(pid)
# device.resume(pid)

# attach附加不影响app执行流程，get_frontmost_application可以获取到最前台的app，懒得去找进程号进程名
app = device.get_frontmost_application()
session = device.attach(app.pid)

jscode = open('script/util.js', encoding='utf-8').read()
script = session.create_script(jscode, runtime='v8')
script.on('message', on_message)
script.load()

script.exports.sodump('sgsecuritybodyso-5.4.66')
# script.exports.memdump1(0x85015000, 0x850ac000)
# script.exports.memdump2(0x9cce3000, 0x3000)

os.system('pause')
