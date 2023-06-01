# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2022/12/1 17:49
import base64
import re
import time

import mitmproxy.http
from colorama import init
from CMBSM.CMBSMFunction import *
import json

init(autoreset=False)

def printf(log, type=1):
    print(f'\033[3{type}m{log}\033[0m')


def sm3_sign(data: dict) -> str:
    """sm3 签名
   :param data:
   :return: 64位 16进制编码字符串
    """
    return CMBSM3Digest(json.dumps(data, separators=(",", ":"),ensure_ascii=False).encode()).hex()


def api_market_sign(appid, secret, sign, private_key=None) -> (str, int):
    """
    api市场接口签名/openapi签名 apisign 生成
    :param private_key: sm2私钥 为空时自动生成 一般为32位bytes或64位16进制
    :param appid:
    :param secret:
    :param sign:
    :return: api_sign 签名
    :return: timestamp int 时间戳
    """
    if private_key is None:
        private_key = CMBSM2KeyGen().get('privatekey')
    if isinstance(private_key, str):
        if len(private_key) == 32:
            private_key = private_key.encode()
        if len(private_key) == 64:
            private_key = bytes.fromhex(private_key)
    timestamp = str(int(time.time()))
    text = f'appid={appid}&secret={secret}&sign={sign}&timestamp={timestamp}'
    print(text)
    print(text)
    api_sign = CMBSM2SignWithSM3(private_key, text.encode())
    return api_sign.hex(), timestamp


class enc_proxy:
    def __init__(self):
        printf("加密加签脚本加载完成")
        self.appid = '6e81d1de-cb08-4d1c-8f59-cab8409beaff'
        self.secrete = '602d30cc-e5b4-47a5-a37b-f8ff94a320a5'
        self.private_key = '2faffd85d14cc587bd2de807a7858e3c2b507992f2ef06753a47455fc4c47cba'
        self.host = 'api.cmburl.cn'

    def match_host(self, host):
        if isinstance(self.host, list):
            return host in self.host
        return host == self.host or re.match(self.host,
                                             host) is not None

    def request(self, flow: mitmproxy.http.HTTPFlow):
        if self.match_host(flow.request.host):
            if flow.request.method == 'POST':
                body = flow.request.json()
                print(body)

                if not isinstance(body,dict) or "encryptInfo" not in body.keys():
                    body = get_enc(body)
                    body['digEvp'] = 'BAaja5CkzACwIh+loJ3UJ6UN+Pp67Ytuct9fjEzjXOoQuditmTcCAmEyibMUpdyyjcfQwzKcn7Vmu/0uhxSGrvUH4nej3QJk12ocaqzFSX91ZFupzCVu4LY7TcvAHrMkUxWegEuFC5TjHJmVcjNIZf0='
                    flow.request.set_text(json.dumps(body,separators=(",", ":"),ensure_ascii=False))
                else:
                    body['digEvp'] = 'BAaja5CkzACwIh+loJ3UJ6UN+Pp67Ytuct9fjEzjXOoQuditmTcCAmEyibMUpdyyjcfQwzKcn7Vmu/0uhxSGrvUH4nej3QJk12ocaqzFSX91ZFupzCVu4LY7TcvAHrMkUxWegEuFC5TjHJmVcjNIZf0='
                    flow.request.set_text(json.dumps(body, separators=(",", ":"), ensure_ascii=False))
                    printf('明文如下：',2)
                    text = decode_sm4_code(body['encryptInfo'])
                    printf(json.dumps(text,separators=(",", ":"),ensure_ascii=False),2)
                printf(f'加签原文 {body}')
                printf(f'加签原文 {body}')
                sm3_sign_str = sm3_sign(body)

                api_sign, timestamp = api_market_sign(appid=self.appid,secret=self.secrete,private_key=self.private_key, sign=sm3_sign_str)
                flow.request.headers['appid'] = self.appid
                flow.request.headers['timestamp'] = str(timestamp)
                flow.request.headers['sign'] = sm3_sign_str
                flow.request.headers['apisign'] = api_sign
                flow.request.headers['verify'] = "SM3withSM2"

    def response(self, flow: mitmproxy.http.HTTPFlow):
        pass


addons = [
    enc_proxy()
]

def encode_sm4_code(payload:dict,key=b'r0SHhxc3gju1K833'):
    printf(f'{payload}')
    enc = CMBSM4EncryptWithECB(key,json.dumps(payload,ensure_ascii=False).encode())
    return base64.b64encode(enc).decode()


def decode_sm4_code(payload:str,key=b'r0SHhxc3gju1K833'):
    enc_text = base64.b64decode(payload.encode())
    data_bytes = CMBSM4DecryptWithECB(key,enc_text)
    return json.loads(data_bytes.decode('utf-8'))


def get_enc(data:dict):
    """
    根据原文获取密文
    :param data:
    :return:
    """
    # sm4_key = os.urandom(16)
    sm4_key = b'r0SHhxc3gju1K833'
    pubk = base64.b64decode('BIi1dPQVKbibcs/6K3LUZLLmPzMUR5QlOTZ80bWO7psLpbk2a7zO/8l1IZ42JmAmQRtaO8LugXmiLNCGewA0Lhk='.encode())
    dig_evp_bytes = CMBSM2Encrypt(pubk,sm4_key)
    dig_evp = base64.b64encode(dig_evp_bytes).decode('utf-8')
    encrypt_info = encode_sm4_code(data,sm4_key)
    return {"digEvp": dig_evp, "encryptInfo":encrypt_info}


if __name__ == '__main__':

    data = {"XACCNBR":"6214830118181337","XDSFMCH":"399210105628046","XMCHADR":"北京-北京市-海淀区-广东省-珠海市-其它区-宝华路6号105室-8486","XMCHCTY":"110100","XMCHNAM":"上海市静安区瑞楠汽配经营部","XMCHNBR":"836102558120397","XMCHPRV":"110000",
"XMCHSTS":"Y","XMCHTYP":"5812","XPOSCFE":68000,"XPOSDFA":661100000,"XPOSDFE":82000,"XRCDVER":"00001","XRGNCOD":"110","XSECFLG":"N","XWEXFEE":88000,"XYLCFEE":71000,"XYLIFEE":69000,"XZFBFEE":66000,"XACCNAM":"test","XCRTDTE":"20230202","XCONNAM":"test","XCONMBR":"1111"}
    enc_text = get_enc(data)
    # enc_text = encode_sm4_code(data)
    # enc_text = "/b9DDtzZ0rwAb1dxXzRyjcLjvqw3Mclt4eKm7+F34JK4CVh3hjEn7dN1/LRlgvL6tKW5gUdDmHnIP9y4kbJp7DGEt6neG8lcS9eDmySxj5aZygvF0fhQGcP38RsK6ryn39QK8zcXPSjnnGHQzeAwqGOqEDDugIxu8WAdruTU3PD8Dv+1IdXV9lPx/22W0jLtxFeR2lhu7N8ZVLeUgNXbc36Q8CQpbc6Yh/L72UClXAAv34k9HXeP0cft1VSxjGTj24h83pmV+vnJrRUq0+/GQO4UrIYXuQaG38d84TeoA2z4ypiPASacsQV264xd9KT5IXnKBfBgnohZNejW/BtLgho72klTBUzftgikhH/V4e7fGJukGbBzPnmAa9lEujb/sydppF0dD3H+J/yua799KFwjR+KrUFbn6tZ8Got6yRSMyBO+c+7/PQ1grmYo45ojYbx+Cb+/D0e2iaUcysiolsMyuizLdD9kOajz+5uz9O/WlUjPt69O6Vca6mCUn2v6xu8KlvpInt/+fBR6tQvD3wEZCUhUb5FMaCNDaJtL9h1M9ftHarfU/Sqy7m9+yWJ/gq40uzw88svMxxRHWvRD0TMnLdCQPATnfAn/l0kH7zC3f4OF/9LCm3UA6z8iSMDwoH24KCVL4fvaR2dGdMhDTVwjf/KjRyHEHwbKrTXUzEsDLmV7IRbNUOS2IvUr0MdLmCR2hutqHhbEU0O0klHIAXNMWzPviRPIKi4LjEDfrPF82CT3ziUve6uzcXU2pBvLn5P3M7JCzCnNnEXKOkLTxQ=="
    # key = b'r0SHhxc3gju1K833'

    payload = decode_sm4_code(enc_text['encryptInfo'])
    print(payload)


