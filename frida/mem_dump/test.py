import sys
import os
import time
import frida
import threading
import json

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
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

jscode = open('test.js', encoding='utf-8').read()
script = session.create_script(jscode, runtime='v8')
script.on('message', on_message)
script.load()

os.system('pause')
