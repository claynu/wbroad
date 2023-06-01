# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2022/12/1 17:49
import base64
import hashlib
import json
import re
import time
from  urllib.parse import urlencode

import mitmproxy.http
from CMBSM.CMBSMFunction import *
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from colorama import init
from gmssl import sm4

init(autoreset=False)


def printf(log, type=1):
    print(f'\033[3{type}m{log}\033[0m')


def change2C1C2C3(data):
    """将加密结果 C1C3C2 转为 C1C2C3
    # C1 = data[0:128]
    # C3 = data[128:128+64]
    # C2 = data[128+64:]
    :param data:
    :return: C1C2C3
    """
    #C1C3C2  其中 C1 固定128 C3 固定64
    return data[0:128]+data[128+64:]+data[128:128+64]

def revert2C1C3C2(data):
    """将加密结果 C1C2C3 转为 C1C3C2
    C1 = data[0:128]
    C2 = data[128:-64]
    C3 = data[-64:]
    print(f'C1C3C2={C1}{C3}{C2}')
    print(f'C1C2C3={C1}{C2}{C3}')
    :param data:
    :return:C1C3C2
    """
    return data[0:128]+data[-64:]+data[128:-64]


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


class openapi_enc_proxy:
    def __init__(self):
        printf("加密加签脚本加载完成", 2)
        self.appid ="f217ae74-51a4-40bc-8c7b-58f10b9da7c2"
        self.secrete = "8eace09c-610d-41d9-8f8f-14c5dcdcbcbb"
        self.verify = 'SM3withSM2'
        self.activeCode = '1878338469047420'
        self.sm3_sign_key = self.base64_and_sm4_decode(self.activeCode,'ikxoFxGE72A3qAhGzRbzqHM8oIw6WfKdTMp9HdPsQu8=')
        self.sm3_sign_key = 'EwHaIbIr7aK2oTk7'
        self.pay_key = 'KyFxqpNFwdevahPx'
        self.sign = ''  # 自行处理 大部分是body sm3 / sha256 / 为空
        self.private_key = 'f9da0cc73eb66165219e3798afb54ed3cff54a0cd5dd0417a4d7d13fb2ca97eb'
        self.public_key = '043b85a200536072df4f756389def0198aca02073693b13b3ffb8d95cfc44b6bb4f6dcac67f9c56564ab822ed4abb6e33c56fe0d2a0d69acde7ff20de1926e42ea'
        self.host = "api.cmburl.cn"  # 域名
        self.cipher = open_api_sign(cipher=self.verify, key=self.private_key)

    def base64_and_sm4_decode(self,key:str,data:str):
        return CMBSM4DecryptWithECB(key.encode(), base64.b64decode(data)).decode()

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
        printf(text)
        api_sign = self.cipher.encode(text.encode())
        return api_sign, timestamp

    def match_host(self, host):
        if isinstance(self.host, list):
            return host in self.host
        return host == self.host or re.match(self.host,
                                             host) is not None

    # open_api 通用签名
    def api_sign(self, flow: mitmproxy.http.HTTPFlow,sign=""):
        # sign 默认为空
        api_sign, timestamp = self.api_market_sign(appid=self.appid, secret=self.secrete, private_key=self.private_key,
                                                   sign=sign,verify=self.verify)
        flow.request.headers['appid'] = self.appid
        flow.request.headers['timestamp'] = str(timestamp)

        flow.request.headers['sign'] = sign
        flow.request.headers['apisign'] = api_sign
        flow.request.headers['verify'] = self.verify

    # 请求相关逻辑在此处修改
    def request(self, flow: mitmproxy.http.HTTPFlow):
        if self.match_host(flow.request.host):
            # body sm2 加密
            if flow.request.method == 'POST':
                try:
                    printf(flow.request.text)
                    data_json = flow.request.json()

                    if 'timestamp' in data_json.keys():
                        data_json['timestamp'] = int(time.time()*1000)
                    if "sign" in data_json.keys():
                        data_json.__delitem__('sign')
                        sign = '&'.join([f'{i}={data_json[i]}' for i in sorted(data_json)]) + '&' +self.sm3_sign_key
                        printf(f'sign原串={sign}',2)
                        sm3_hash = CMBSM3Digest(sign.encode())
                        printf(f'sm3_hash值={sign}',2)
                        sign = base64.b64encode(sm3_hash).decode()
                        printf(f'base64编码后sign={sign}',2)
                        data_json['sign'] = sign
                        flow.request.set_text(json.dumps(data_json,ensure_ascii=True))
                    if "paySign" in data_json.keys():
                        data_json.__delitem__('paySign')
                        data_json.__delitem__('txText')
                        sign = '&'.join([f'{i}={data_json[i]}' for i in sorted(data_json)]) + '&' + self.pay_key
                        printf(f'sign原串={sign}', 2)
                        sm3_hash = CMBSM3Digest(sign.encode())
                        printf(f'sm3_hash值={sign}', 2)
                        sign = base64.b64encode(sm3_hash).decode()
                        printf(f'base64编码后sign={sign}', 2)
                        data_json['sign'] = sign
                        flow.request.set_text(json.dumps(data_json, ensure_ascii=True))
                except Exception as e:
                    raise e
            self.api_sign(flow, sign="")
            # headers 签名 如果有其他处理操作，建议放在方法末尾



    def response(self, flow: mitmproxy.http.HTTPFlow):
        if self.match_host(flow.request.host):
            if flow.request.path == '/epay/device/open-api/face/exchange-key':
                res_json = flow.response.json()
                self.pay_key = self.base64_and_sm4_decode(self.sm3_sign_key,res_json['body']['payKey'])
                printf(f'self.paykey={self.pay_key}')
            try:
                res_json = flow.response.json()
                if flow.request.method == 'POST' and "retData" in res_json:
                    ...
            except Exception as e:
                print(e.args)


addons = [
    openapi_enc_proxy()
]

if __name__ == '__main__':
    paykey = 'ikxoFxGE72A3qAhGzRbzqHM8oIw6WfKdTMp9HdPsQu8='
    paykey = '5WNkCA5JoBJsX61eTeNP34eTC3CKcR87o/VhmoJ9dGo='
    code = 'EwHaIbIr7aK2oTk7'
    paykey_bytes = base64.b64decode(paykey)
    pay_key = CMBSM4DecryptWithECB(code.encode(),paykey_bytes)
    print((pay_key))
    print(base64.b64encode(pay_key))
