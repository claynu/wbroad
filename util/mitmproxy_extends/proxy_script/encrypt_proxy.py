# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2022/12/1 17:49
import hashlib
import re
import time

import mitmproxy.http
from CMBSM.CMBSMFunction import *
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from colorama import init

init(autoreset=False)


def printf(log, type=1):
    print(f'\033[3{type}m{log}\033[0m')


class open_api_sign:
    def __init__(self, cipher='SM3withSM2', key=None):
        """ 初始化
        :param cipher:str 加密算法 固定四种
        :param key:
        """
        self.cipher = cipher
        self.key = key
        self.alg = {  # str -> func 映射  使用方法 self.alg['SM3withSM2'](args) 即可
            "SM3withSM2": self.sm3_with_sm2, # DONE
            "SHA256withRSA": self.sha256_whit_rsa,  # 未验证
            "SHA256Verify": self.sha256,  # 未验证
            "HmacMd5Verify": None  # TODO
        }
        if cipher not in self.alg.keys():
            printf(f'!! 加签算法未定义 verify = {cipher} not in {self.alg.keys()}', 1)
        # 处理不同算法的key
        elif cipher == 'SM3withSM2':
            if key is None:
                self.key = CMBSM2KeyGen().get('privatekey')
            if isinstance(key, str):
                if len(key) == 32:
                    self.key = key.encode()
                if len(key) == 64:
                    self.key = bytes.fromhex(key)
            print(f'SM3withSM2 KEY = {self.key}')
        elif cipher == 'SHA256withRSA':
            if not self.key.startswith('-----BEGIN PUBLIC KEY'):
                self.key = '''-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----'''.format(self.key)
            print(f'SHA256withRSA KEY = {self.key}')

    def sm3_with_sm2(self, data: bytes) -> str:
        return CMBSM2SignWithSM3(privkey=self.key, msg=data).hex()

    def sha256(self, data: bytes) -> str:
        """
        sha256
        :param data:
        :return:
        """
        hash = hashlib.sha256()
        hash.update(data)
        return hash.hexdigest()

    def sha256_whit_rsa(self, data: bytes) -> str:
        """
        rsa 加密
        :param publick_key: 公钥 str
        :param data:   明文
        :return:
        """
        rsakey = RSA.importKey(self.key)
        cihper = PKCS1_v1_5.new(rsakey)
        cipher_text = cihper.encrypt(data.encode())
        cipher_text = self.sha256(cipher_text)
        return cipher_text

    def encode(self, data: bytes) -> str:
        return self.alg[self.cipher](data)


class enc_proxy:
    def __init__(self):
        printf("加密加签脚本加载完成", 2)
        self.appid = '725a0750-59fe-4741-bfe9-cd5d8396ebbc'
        self.secrete = '94010b6e-33cf-48a7-bdd6-d4326f908415'
        self.verify = 'SHA256Verify'
        self.sign = ''  # 自行处理 大部分是body sm3 / sha256 / 为空
        self.private_key = '63c7e58688f9404c89c1b5bc22cdc408'
        self.host = "api.cmburl.cn"  # 域名
        self.cipher = open_api_sign(cipher=self.verify, key=self.private_key)

    def api_market_sign(self, appid, secret, sign, private_key=None, verify="SM3withSM2") -> (str, int):
        """
        api市场接口签名/openapi签名 apisign 生成
        :param private_key: sm2私钥 为空时自动生成 一般为32位bytes或64位16进制
        :param appid:
        :param secret:
        :param sign:
        :return: api_sign 签名
        :return: timestamp int 时间戳
        """
        timestamp = int(time.time())
        text = f'appid={appid}&secret={secret}&sign={sign}&timestamp={timestamp}'
        api_sign = self.cipher.encode(text.encode())
        return api_sign, timestamp

    def match_host(self, host):
        if isinstance(self.host, list):
            return host in self.host
        return host == self.host or re.match(self.host,
                                             host) is not None

    # open_api 通用签名
    def api_sign(self, flow: mitmproxy.http.HTTPFlow):
        # sign 默认为空
        api_sign, timestamp = self.api_market_sign(appid=self.appid, secret=self.secrete, private_key=self.private_key,
                                                   sign=self.sign)
        flow.request.headers['appid'] = self.appid
        flow.request.headers['timestamp'] = str(timestamp)
        flow.request.headers['sign'] = self.sign
        flow.request.headers['apisign'] = api_sign
        flow.request.headers['verify'] = self.verify
        printf(flow.request.headers, 2)

    # 请求相关逻辑在此处修改
    def request(self, flow: mitmproxy.http.HTTPFlow):
        if self.match_host(flow.request.host):
            # headers 签名 如果有其他处理操作，建议放在方法末尾
            self.api_sign(flow)

    def response(self, flow: mitmproxy.http.HTTPFlow):
        pass

from openapi_sign import openapi_enc_proxy
addons = [
    # enc_proxy(),
    openapi_enc_proxy()
]