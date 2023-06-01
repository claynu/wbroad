# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2022/12/1 17:49
import datetime
import json
import os
import re
import random

import mitmproxy.http
import yaml
from colorama import init

from ...bin import util


init(autoreset=False)
config = yaml.safe_load(open('./global_config.yaml', 'r', encoding='utf-8'))

def printf(log, type=1):
    print(f'\033[3{type}m{log}\033[0m')


class enc_proxy:
    def __init__(self):
        printf("加密加签脚本加载完成")
        self.key = bytes.fromhex('01' * 32)
        self.host = config['target']['host']

    def match_host(self, host):
        if isinstance(self.host, list):
            return host in self.host
        return host == self.host or re.match(self.host,
                                             host) is not None

    def request(self, flow: mitmproxy.http.HTTPFlow):
        if flow.request.method == 'GET':
            path = flow.request.path
            g = "j9da6fld2khgz2chd354czbfd2b2fs3ea"
            path = format_get_params(path)
            encode_data = f"url={path}&body={g}"
            printf(f"path = {path}---encode_data={encode_data}")
            flow.request.headers['Sign'] = util.md5_encrypt(encode_data)
            print(f'Sign = {flow.request.headers["Sign"]}')

        if flow.request.method == 'POST':
            path = flow.request.path
            body = flow.request.json()
            printf(body, 2)
            g = "j9da6fld2khgz2chd354czbfd2b2fs3ea"
            encode_data = f"url={path}&body={json.dumps(body).replace(' ', '')}{g}"
            flow.request.headers['Sign'] = util.md5_encrypt(encode_data)
            print(f'Sign = {flow.request.headers["Sign"]}')

        if flow.request.path in ["/ibank-pbanking/login/logout","/ibank-pbanking/cmf-app/appUpaInfo","/ibank-pbanking/secure/keyAgreement","/ibank-pbanking/secure/exchangePubKey","/ibank-pbanking/swagger-resources","/ibank-pbanking/swagger-resources/configuration/ui","/ibank-pbanking/secure/enableEcode","/ibank-pbanking/language/getAllLanguage","/ibank-pbanking/secure/getRandomNum","/ibank-pbanking/biz/run"]:
            return
        try:
            data = json.dumps(flow.request.json(), separators=(',', ':'))
            aad = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            iv = os.urandom(12)
            crypt_text = util.aes_encrypt(self.key, iv, aad, data)
            format_data = {
                'payload': crypt_text,
                'aad': aad,
                'iv': util.base64_encode(iv)
            }
            data = json.dumps(format_data, separators=(',', ':'))
            printf(data, 2)
            flow.request.set_text(data)
        except Exception as e:
            return

    def response(self, flow: mitmproxy.http.HTTPFlow):
        try:
            res = flow.response.json()
            printf(f'res={res}',2)

            if 'data' in res.keys() and res.get('data') is not None  and 'pubKey' in res.get('data',{}).keys():
                key_bytes = res.get('data', {}).get('pubKey', '5')
                self.key = bytes.fromhex(f'0{key_bytes}' * 32)
                printf(f'密钥更新为05',2)

            if 'errCode' in res.keys() and res.get('errCode') == '81J0118':
                if self.key > bytes.fromhex(f'01' * 32):
                    self.key = bytes.fromhex(f'01' * 32)
                else:
                    self.key = bytes.fromhex(f'05' * 32)
                printf(f'加密失败 密钥更新为{self.key}',2)

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
            printf(e.args)


def format_get_params(path):
    params_str = path.split("?")
    l = []
    if len(params_str) > 1:
        params = params_str[1].split('&')
        params.sort()
        for param in params:
            if param.split('=')[1] != '':
                l.append(param)
        if l == []:
            return params_str[0]
        return params_str[0] + '?' + '&'.join(l)
    else:
        return path

addons = [
    enc_proxy()
]

