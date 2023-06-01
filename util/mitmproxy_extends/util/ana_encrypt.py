# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2023/2/7 9:07
import os
import sys
import unicodedata

from enc_util import *
import re
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler, FileSystemEventHandler

#
# def test():
#     base64_match = "^[a-zA-Z0-9=+/]{1,}$"
#     aes_match = "^[a-zA-Z0-9+=/]{1,}$"
#     text =  'test original text'
#     enc_text = aes_ecb_encrypt(bytes.fromhex('05'*16).decode(),text)
#     print(enc_text)
#     print(len(enc_text))
#
#     res = re.findall("^[a-zA-Z0-9+=]{1,}$",enc_text)
#     print(res)

import logging
import re

class fileModify(FileSystemEventHandler):
    def __init__(self):
        FileSystemEventHandler.__init__(self)
    
    def on_modified(self, event):
        if "global_config.yaml" == event.src_path.split(os.sep)[-1]:
            print(f'global_config.yaml  {event.src_path} changed !')


if __name__ == '__main__':
    s = os.path.abspath('.')
    print(s)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s',datefmt='%Y-%m-%d %H:%M:%S')
    path = r'D:\TOOLS\工具\permission_check\version3'
    event = fileModify()
    obs = Observer()
    obs.schedule(event,path,recursive=True)
    obs.start()
    while 1:
        ...
    obs.join()
