# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2022/12/1 17:49
# describe: 解密请求


import mitmproxy.http
from colorama import init
from ...bin import util

init(autoreset=False)


import yaml
import re


def printf(log, type=1):
    print(f'\033[3{type}m{log}\033[0m')


class dec_proxy:
    def __init__(self, config):
        target = config['target']
        printf("解密脚本加载完成")
        self.host = target['host']

    def match_host(self, host):
        if isinstance(self.host, list):
            return host in self.host
        return host == self.host or re.match(self.host,
                                             host) is not None

    def request(self, flow: mitmproxy.http.HTTPFlow):
        # 解密请求
        if self.match_host(flow.request.host):
            try:
                res = flow.request.json()
            except Exception as e:
                return
            if res is None: return
            if 'aad' in res.keys() and 'iv' in res.keys():
                aad = res['aad']
                iv = util.base64_decode(res['iv'])
                try:
                    key = bytes.fromhex('01' * 32)
                    result = util.aes_decrypt(key, iv, aad, res.get('payload', res.get('encrypt', '')))
                    flow.request.set_text(result)
                except Exception as e:
                    key = bytes.fromhex('05' * 32)
                    result = util.aes_decrypt(key, iv, aad, res.get('payload', res.get('encrypt', '')))
                    flow.request.set_text(result)


    def response(self, flow: mitmproxy.http.HTTPFlow):
        try:
            res = flow.response.json()
            if res is None: return
            if 'aad' in res.keys() and 'iv' in res.keys():
                aad = res['aad']
                iv = util.base64_decode(res['iv'])
                try:
                    key = bytes.fromhex('01' * 32)
                    result = util.aes_decrypt(key, iv, aad, res.get('encrypt', res.get('payload', '')))
                    flow.response.set_text(result)
                except Exception as e:
                    key = bytes.fromhex('05' * 32)
                    result = util.aes_decrypt(key, iv, aad, res.get('encrypt', res.get('payload', '')))
                    flow.response.set_text(result)
        except Exception as e:
            return
