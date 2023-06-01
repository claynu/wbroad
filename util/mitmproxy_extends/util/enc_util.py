# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2022/10/18 14:24
# describe: 常用加密加签方法

import base64
import hashlib
import hmac
import json
import time
import urllib

import requests
from CMBSM.CMBSMFunction import *
from CMBSM.utils import com
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


def sm2_encrypt(public_key: str, data: str) -> str:
    """ sm2 加密、 如果前端加密使用 msk-lib-min.js或者公钥和密文固定以04开始 则说明使用的行内国密加密
    :param public_key 加密公钥 行内固定前缀 04
    :param data 待加密数据
    """
    enc_data = CMBSM2Encrypt(com.aschex_to_bcdhex(public_key), data)  # sm2加密
    return enc_data


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
    enc_bytes = cip.encrypt(data)
    print(enc_bytes)
    enc_text = base64_encode(enc_bytes)
    return enc_text


def aes_ecb_decrypt(key: str, data: bytes) -> str:
    data = base64_decode(data)
    cip = AES.new(key.encode(), AES.MODE_ECB)
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
    timestamp = int(time.time())
    text = f'appid={appid}&secret={secret}&sign={sign}&timestamp={timestamp}'
    print(text)
    api_sign = CMBSM2SignWithSM3(private_key, text.encode())
    return api_sign.hex(), timestamp


def sm3_sign(data: dict) -> str:
    """sm3 签名
   :param data:
   :return: 64位 16进制编码字符串
    """
    return CMBSM3Digest(json.dumps(data, separators=(",", ":")).encode()).hex()


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
    appid = '6e81d1de-cb08-4d1c-8f59-cab8409beaff'
    secrete = '602d30cc-e5b4-47a5-a37b-f8ff94a320a5'
    private_key = '2faffd85d14cc587bd2de807a7858e3c2b507992f2ef06753a47455fc4c47cba'
    data = {"digEvp": "MHkCIGz5VFrq7hV81fn55JTrEvVJQ5EyG29t2Hm8uLQI1mSzAiEAq0NDlIqaHOU4vBNu7SWrpD+AFF7H1UKIIgPnmeZt5SUEIK9Q67586Mc3JCpjXgRSGFDo9mj3wLN12G40CW31wWalBBCnEPhpI70FAd6EG+rczg3c", "digEvpEncMth": "SM2", "encoding": "UTF-8", "encryptInfo": "t5YxJ95ZJmSqV11/LyJKtUKuJEGSBqTrFeAb5ms41lqjTwlCmVokOvnUb9b4LVp1ls4NptHJ0m31iiiAncmjgmRPHFV3p1yMKs7SWNetr0ViaOwn2KnBNJTxJScub76vfQoK8YFRPcAeLGbWjp6NVPzM7HYM2vfVkc5kMMFFbaN706dMk5it8+RmMeYkP3FdCdtOQ3Uea5igc60yBxtNzKbOETOuhSLVtnUrDpszDNq1xSPNZr1bjcsj+o+5vOGUjjAmtf1ydYrIxJkPIGL8iVJrq+vcpRj5i8oOaT+qhXKty9pMPXGmNvaim/vOag6ukn25EaJCLtrSFUKR5wzJ/YWF2FxQvqCXioQzq0ftYt4zqPbGqTnAdEyXxW039hcn/v61as+uO013yaUSCio31IVxB6yYeHDDdmMN3FiXBxPlh+tE24faMC7jhG0i+j4EvmqV+9+22UlKrUWraDHgF0iNVWfdeqMG5IgwYfbPqCRIdCd+qG4o2z9SBAZZ7GpsVHNBrGsoua21Jval+AgH5ZWge9li7sg7aJ3Kc5KEVq1VhdPLTjE+j8FviVnGZUGtJ6q3NFGfkR8rTQdbAavjxdW1oJfJK63cULLOuC7iyLcqHNruC4Tt+Z+e2FT2H3Kb3O6cD35l3tz3Eu3HnqxZViH4Y8eD2S0N08MmD6fbL7puLr3B13VWzb9NP1z3pQIZ8DEP+4jVqFQASWgZKOKmxYuY+QTY5yR3x6WWdP7oNafARA+SCIYfq9bC9KOVRafYJcG7CuSAc7VvHobZaWnnL2rDCWUXXxYMJ/Nm0XSV9K2zy8BtaeZBc9e6c7MWXlJU56lmptQqIvUze3N3fU+Y55yQRh+tCejv2YfiDq3j0frlMpT+fmj5Ayv5Lta9fk1zocaoWtRtIll4jWI7JwZfeaHGqFrUbSJZeI1iOycGX3mhxqha1G0iWXiNYjsnBl95p0yi9YV/VJJkm3oZkPPwQPAIeSEjyFkxtVupf0AwXLYz86WDrJG1r+6jLRIxIcoq", "encryptMethod": "SM4", "merId": "394564641654654", "sign": "", "version": "0.0.1"}
    print(sm3_sign(data))

    sign = CMBSM3Digest(json.dumps(data, separators=(",", ":")).encode()).hex()
    # sign = '1'
    apisign, timestamp = api_market_sign(appid=appid, secret=secrete, sign=sign,
                                         private_key=private_key)
    print(f'''
content-type:application/json
appid:{appid}
timestamp:{timestamp}
sign:{sign}
apisign:{apisign}
verify:SM3withSM2
''')
    print(sign, timestamp)
    # s = timestamp2date('1670204828629')
    # print(s)
    # s = datetime2timestamp(s)
    # print(s)

    # data = "mb+tdixznGwT5ko6B8FMb8bdoOvzCZvB89cLUt7WwiHj6mU0AarZYsKHO3HRFp0ZmmLKhjWnVogrtoMNGgPsEGDn5mf+OQaEvsLAM2iFeWnjZ3gJnFXsnNENEeu1lWsi3wFpylDt1B86xBbsL0R/Pyig4OllFDWYmimtWaoqy+bdAkzK5X0Afra/PMszju+NSAEcOBoQr/goUzB9FlRxdxQ/eeeQdxdp/dSCklax24O7izNLCsT3uBG2b35+xiC8yicxqW2aMK8JBRd/AXNrCAw80+H2fFtLHaLsUpuOqJ7PWGy0z9fs0sNHqSflFEss6FDCr+t6Ed/u/8xa473Wyg=="
    # data = padding(data.encode(),16)
    # cip = AES.new('s1q7Dn1q9C9m5J160b3LEV8HkGOcABWB'.encode(), AES.MODE_ECB)
    # s = cip.encrypt(data)
    # print(s)
    # print(base64_encode(s))

    """
    headers['aesKey'] = rsa(res.json()['publickKey'],res.json()['aesKey'])
    headers['sign'] = sha256(f'url={path}&body={body.get_text()}czl42bk4ocm682czg2vrs3elq6cas9qfd')
    """

    public = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvfzEieVcKTGWeRQVagK7zSqL2YvT1ygf8cy5g3nXasjqTtKwA/g4psRLp/f+72pM0dflFKzc4/Mh5Tia2NYKEO0aa8PVo3Xv+eE5vcKtcRmgZAx76/mHAzFjvrT8DToDBDDkxUxkWkYHANqMX0ABlHgoCQ2h7qMHwAOVynmVY/CzBCqe+4SOqQph45YTcykTb7mvO/oLQ3MQ3MY2/1sjqN2vvGC75kLjakrF0mIASuRtJVcYy/I3CClB17aL/hGREaugkpJMYvSv81DzkAuor72v0r7X5xgOLmGLDeAn9fn5jMrLTlhHyJJFFTYlqd2n9hUgABiWGZeed60dwcFwgwIDAQAB'
    url_params = {
        "startDate": "20221026",
        "endDate": "20221125",
        "pageNum": 1,
        "pageSize": 10
    }
    aeskey = "ZozDjOw0K1pyMqTUeE4zkXFiH5QqntDD"
    enc = rsa_encrypt(public, aeskey)  # headers['aesKey']
    print(enc)
    path = "/ocm/uass/notice/info"
    sign_template = f"url={path}?{'&'.join([f'{i}={url_params[i]}' for i in sorted(url_params)])}&body=czl42bk4ocm682czg2vrs3elq6cas9qfd"
    print(sign_template)
    print(
        'url=/ocm/uass/notice/info?endDate=20221125&pageNum=1&pageSize=10&startDate=20221026&body=czl42bk4ocm682czg2vrs3elq6cas9qfd')
    print(sha256(sign_template.encode()))
    print(sha256(
        b"url=/ocm/uass/notice/info?endDate=20221125&pageNum=1&pageSize=10&startDate=20221026&body=czl42bk4ocm682czg2vrs3elq6cas9qfd"))
    #  aes 加密
    data = json.dumps(url_params, separators=(',', ':'))
    s = aes_ecb_encrypt(aeskey, data)
    print(s)
    print(aes_ecb_decrypt(aeskey, b'816FpkBYCWvpkARqOzuCdM0MWs/Gs8ipqiZ9XbRtIQI='))
