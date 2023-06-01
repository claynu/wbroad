# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2023/2/2 9:48
import base64
import json

from Crypto.Cipher import AES
import mitmproxy.http
import requests
from colorama import init

init(autoreset=False)

def padding(data: bytes, length) -> bytes:
    """
    PKCS7填充
    :param data:
    :param length:
    :return:
    """
    pad_size = length - len(data) % length
    if pad_size != 0:
        data = data + bytes.fromhex(f"{hex(pad_size).split('0x')[-1].rjust(2).replace(' ', '0')}" * pad_size)
    return data


def unpadding(data: bytes) -> bytes:
    """
    PKCS7 清理填充
    :param data:
    :param length:
    :return:
    """
    length = len(data)
    pad_length = ord(data[length - 1])
    pad_bytes = data[length - pad_length:]
    if pad_bytes == pad_bytes[-1] * pad_length:
        data = data[0:length - pad_length]
    return data

cip = AES.new('Szjx2022@666666$'.encode('utf-8'),AES.MODE_ECB)

def aes_ecb(data:str):
    crypto_text = cip.encrypt(padding(data.encode('utf-8'),16))
    return base64.b64encode(crypto_text).decode()


def printf(log, type=1):
    print(f'\033[3{type}m{log}\033[0m')


class dec_proxy:
    def __init__(self):
        printf("sql扫描异常响应处理代理", 2)

    def request(self, flow: mitmproxy.http.HTTPFlow):
        if flow.request.method =='POST':
            req = flow.request
            data = req.json()
            password = data.get('pw','')
            data['pw'] = aes_ecb(password)
            flow.request.set_text(json.dumps(data))


addons = [dec_proxy()]



if __name__ == '__main__':
    key_word = ["admin","Szjx2022",'@','666666','$','arius',"logiem"]

