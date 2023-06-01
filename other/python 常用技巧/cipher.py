# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2022/10/18 14:24
# describe: 常用加密加签方法

import base64
import datetime
import hashlib
import hmac
import json
import os
import time
import urllib

import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

requests.packages.urllib3.disable_warnings()


def base64_encode(data: str) -> str:
    """ 对参数进行base64 编码
    :param data:str 待编码数据
    :return str:str 编码后的数据
    """
    if isinstance(data, str):
        data = data.encode()
    data_encode = base64.b64encode(data)
    return data_encode.decode()


def base64_decode(data: str) -> bytes:
    """ 对参数进行base64 解码
    :param data:str 待解码数据
    :return str:str/bytes 编码后的数据
    """
    if isinstance(data, str):
        data = data.encode()
    # str -> bytes
    data_encode = base64.b64decode(data)
    return data_encode


def md5_encrypt(data: bytes) -> str:
    """ md5 加密
    :param data:str  待加密数据
    :return str:str  编码后的数据
    """
    if isinstance(data, str):
        data = data.encode()
    md5 = hashlib.md5()  # hashlib 有常见的hash算法 sha256 sha1 等等
    md5.update(data)
    return md5.hexdigest()


def url_encode(data: str) -> str:
    """ url 编码
    :param data:str  待编码数据
    :return str:str  编码后的数据
    """
    return urllib.parse.quote(data)


def url_decode(data: str) -> str:
    """ url 解码
    :param data:str  待解码数据
    :return str:str  解码后的数据
    """
    return urllib.parse.unquote(data)

#
# def sm2_encrypt(public_key: str, data: str) -> str:
#     """ sm2 加密、 如果前端加密使用 msk-lib-min.js或者公钥和密文固定以04开始 则说明使用的行内国密加密
#     :param public_key 加密公钥 行内固定前缀 04
#     :param data 待加密数据
#     """
#     enc_data = CMBSM2Encrypt(com.aschex_to_bcdhex(public_key), data)  # sm2加密
#     return enc_data


def aes_encrypt(key=b'', iv=os.urandom(12), aad=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), data='') -> str:
    """ 本例为aes 的aes-256-gcm 加密
    :param key:
        It must be 16, 24 or 32 bytes long (respectively for *AES-128*,
        *AES-192* or *AES-256*).
    :param iv:
       偏移量
    :param aad:
        auth_tag 加密的签名校验作用
    :param data:
        需加密的数据
    :return payload:
        密文+tag 的base64编码后的str
    """
    cip = AES.new(key, AES.MODE_GCM, iv, mac_len=16)
    cip.update(aad.encode('utf-8'))
    crypto_text, tag = cip.encrypt_and_digest(data.encode('utf-8'))
    payload = base64.b64encode(crypto_text + tag).decode('utf-8')
    # res = {'payload':payload,'iv':base64.b64encode(iv).decode(),'aad':aad}
    return payload


def aes_decrypt(key: bytes, iv: bytes, aad: str, crypt_text: bytes) -> str:
    """ 本例为aes 的aes-256-gcm 加密
    :param key:
        It must be 16, 24 or 32 bytes long (respectively for *AES-128*,
        *AES-192* or *AES-256*).
    :param iv:
       偏移量
    :param aad:
        auth_tag 加密的签名校验作用
    :param crypt_text:
        需解密的数据
    :return result:
        明文
    """
    cip = AES.new(key, AES.MODE_GCM, iv, mac_len=16)
    cip.update(aad.encode('utf-8'))
    crypt_text = base64_decode(crypt_text)
    tag = crypt_text[-16:]
    crypt_text = crypt_text[0:-16]
    result = cip.decrypt_and_verify(crypt_text, tag)
    return result.decode('utf-8')


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


def rsa_encrypt(publick_key: str, data: str) -> bytes:
    """
    rsa 加密
    :param publick_key: 公钥 str
    :param data:   明文
    :return:
    """
    if not publick_key.startswith('-----BEGIN PUBLIC KEY'):
        publick_key = '''-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----'''.format(publick_key)
    print(publick_key)
    rsakey = RSA.importKey(publick_key)
    ciper = PKCS1_v1_5.new(rsakey)
    cipher_text = ciper.encrypt(data.encode())
    ciper_text = base64_encode(cipher_text)
    return ciper_text


def sha256(data: bytes) -> str:
    """
    sha256
    :param data:
    :return:
    """
    hash = hashlib.sha256()
    hash.update(data)
    return hash.hexdigest()


def aes_ecb_encrypt(key: str, data: str) -> str:
    """
    aes ecs 加密
    :param key: 密钥
    :param data:  明文
    :return:
    """
    data = padding(data.encode(), 16)
    cip = AES.new(key.encode(), AES.MODE_ECB)
    enc_text = base64_encode(cip.encrypt(data))
    return enc_text


def aes_ecb_decrypt(key: str, data: bytes) -> str:
    data = base64_decode(data)
    cip = AES.new(key.encode(), AES.MODE_ECB)
    text = cip.decrypt(data)
    return unpadding(text.decode())


def aes_cbc_decrypt(key: str, data: bytes, iv:bytes) -> str:
    data = base64_decode(data)
    cip = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    text = cip.decrypt(data)
    return unpadding(text.decode())


def timestamp2date(timestamp: str, format='%Y-%m-%d %H:%M:%S') -> str:
    """
    时间戳 转 格式化日期字符串
    strptime format_date => time
    strftime time => format_date
    :param format:
    :param timestamp 10位时间戳 数据类型为str:
    :return:
    """
    return time.strftime(format, time.localtime(int(timestamp[0:10])))


def datetime2timestamp(datastr: str, format='%Y-%m-%d %H:%M:%S') -> str:
    """
    格式化日期字符串 转 时间戳
    :param datastr:
    :param format:
    :return:  10 位时间戳
    """
    return str(int(time.mktime(time.strptime(datastr, format))))





def za24_sm4_decode(payload: dict) -> dict:
    """
    安全室sm4解密接口 (密钥在加密机，无法获取)
    :param payload:dict : 密文
    :return: dict 明文
    """
    url = "http://za24test75.uat.cmbchina.net:8080/test/decodeWithSm4"

    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, json=payload, verify=False)
    return response.json()


def za24_sm4_encode(payload: dict) -> (str,str):
    """
    安全室sm4加密接口 (密钥在加密机，无法获取)
    :param payload:json body
    :return:  (zDigEvp，zCipTxt)
    """
    url = "http://za24test75.uat.cmbchina.net:8080/test/encodeWithSm4"
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, json=payload, verify=False)
    try:
        if "zDigEvp:" in response.json().keys():
            return response.json()["zDigEvp:"], response.json()["zCipTxt:"].strip(),
        else:
            print("解密失败！")
    except Exception as e:
        print(f"解密失败！ e = {e.args} {e.__cause__}")
    return "", ""



if __name__ == '__main__':

    ...


