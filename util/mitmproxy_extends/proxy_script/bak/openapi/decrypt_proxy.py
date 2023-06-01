# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2022/12/1 17:49
# describe: 解密请求


import mitmproxy.http
from colorama import init
import sys
import os
bin_path = os.path.abspath(__file__+'../../../../bin')
sys.path.append(os.path.abspath(bin_path))
import util

init(autoreset=False)


import yaml
import re
import requests
import json


def printf(log, type=1):
    print(f'\033[3{type}m{log}\033[0m')


def decode_sm4(payload):
    url = "http://za24test75.uat.cmbchina.net:8080/test/decodeWithSm4"

    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, json=payload,verify=False)
    return response.json()


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
                data = flow.request.json()
            except Exception as e:
                return
            if data is None: return
            text = decode_sm4(data)
            flow.request.set_text(json.dumps(text,separators=(",",":"),ensure_ascii=False))



    # def response(self, flow: mitmproxy.http.HTTPFlow):
    #     try:
    #         res = flow.response.json()
    #         if res is None: return
    #         if 'aad' in res.keys() and 'iv' in res.keys():
    #             aad = res['aad']
    #             iv = util.base64_decode(res['iv'])
    #             try:
    #                 key = bytes.fromhex('01' * 32)
    #                 result = util.aes_decrypt(key, iv, aad, res.get('encrypt', res.get('payload', '')))
    #                 flow.response.set_text(result)
    #             except Exception as e:
    #                 key = bytes.fromhex('05' * 32)
    #                 result = util.aes_decrypt(key, iv, aad, res.get('encrypt', res.get('payload', '')))
    #                 flow.response.set_text(result)
    #     except Exception as e:
    #         return
if __name__ == '__main__':
    data = (decode_sm4({"digEvp":"BIYB224JjBYSZJ0T6tFuEw6A3GT4HyQIVpluwuKtGpDv/qyk5cT8MYebWre4M3qJNvoxb+HHZunme1010i/nb+MZEJkyu9zBgjaF1wdD7upAfD+jyp8guv2jzm/lMQq8BP0dHZjengWpvt+0YZ6CPBk=","encryptInfo":"Pzp+uTY2243pPxR37Ga4hMQ2HPO8yJF6kvO8ELuWms+pPVvIV5szOWcG1VAk7ZfZZJ0zFwG+hip2wEMKVdHIyXGSeoqgbGUt4+Ig6weDtbA="}))
    print(data)
    print(json.dumps(data,separators=(",",":"),ensure_ascii=False))
