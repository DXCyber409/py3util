import frida, sys
import time

def on_message(message, data):
    print(message)
    if message['type'] == 'send':
        print(message['payload'])
        if (data is not None):
            with open(('dump/%s' % message['payload']), mode='wb') as f:
                f.write(data)
            print('[+]Dump %s ok' % message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])

jscode = open('script/test.js', encoding='utf-8').read()

# device = frida.get_usb_device(0)
# pid = device.spawn(["com.unionpay"])
# session = device.attach(pid)
# device.resume(pid)

session = frida.get_usb_device(0).attach('com.vnpay.bidv')

script = session.create_script(jscode, runtime='v8')
script.on('message', on_message)
# time.sleep(15)
script.load()
sys.stdin.read()
