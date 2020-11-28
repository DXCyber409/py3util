import os

for d in os.listdir('dump'):
    if not d.__contains__('.so'):
        continue
    parts = d.split('.')
    src_path = os.path.join('dump', d)
    base_name = parts[0]
    base_addr = parts[2]
    out_name = "fix/" + base_name + ".fix.so"
    cmd = './sofix %s %s %s' % (src_path, base_addr, out_name)
    print(cmd)
    print(os.system(cmd))
