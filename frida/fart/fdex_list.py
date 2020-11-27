#! /usr/bin/python2.7
# -*- coding: utf8 -*-
import os

repair_map = {}

# 添加需要修复的dex列表
for dir in os.listdir('.'):
    if (dir.endswith("_dexfile.dex")):
        if not repair_map.__contains__(dir):
            repair_map[dir] = ""

# 添加需要可以使用的指令列表
for dir in os.listdir('.'):
    for k,v in repair_map.items():
        if dir.endswith(".bin") and (dir.split('_')[0] == k.split('_')[0]) and len(v) == 0:
            repair_map[k] = dir

# 对可以修复的dex文件进行操作
for k,v in repair_map.items():
    print "python fart.py -d %s -i %s" % (k,v)

