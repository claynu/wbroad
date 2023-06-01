# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2022/12/1 17:49
# describe: 解密请求


import mitmproxy.http
from colorama import init

from proxy_script.bin import util

init(autoreset=False)

import re
import json


def printf(log, type=1):
    print(f'\033[3{type}m{log}\033[0m')


class dec_proxy:
    def __init__(self, config):
        target = config['target']
        printf("解密脚本加载完成", 2)
        self.host = target['host']

    def match_host(self, host):
        if isinstance(self.host, list):
            return host in self.host
        return host == self.host or re.match(self.host,
                                             host) is not None

    def request(self, flow: mitmproxy.http.HTTPFlow):
        # 解密请求
        return