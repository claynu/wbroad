### python 常用技巧
[TOC]

#### 0x01 字典排序

```python
# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2023/2/27 10:12

def sort_dict_by_desc(data:dict) -> dict:
    res_dict = {}
    data_list = sorted(data.items(), key=lambda x: x[1]["description"], reverse=False)
    for item in data_list:
        res_dict[item[0]] = item[1]
    return res_dict


if __name__ == '__main__':
    dd = {'71629': {'execName': '链管理/链：描述存在水平越权', 'bugId': 7688, 'image': '<p>1.使用管理员账号与母子链管理员账号，抓取修改链管理模块的链描述的数据包（母子链管理员无法查看管理员内的链）</p><p>2.查看数据包，发现根据链ID进行链的区分，将管理员链的ID替换至母子链管理员的数据包内，重放数据包后，显示成功，描述被更改</p><p><img src="http://99.13.135.227:8080/images/image20230224090010.png" title="image20230224090010.png" alt="image.png" style="max-width:100%"/></p>', 'description': '', 'execUserName': '宁逸铭', 'execUserId': 122, 'case_id': 43649, 'exec_type': '横向越权测试'}, '71634': {'execName': '跨链适配器：暂停存在水平越权', 'bugId': 7689, 'image': '<p>1.修改适配器内的告警设置，根据PUT后的链ID确认修改对象</p><p><img src="http://99.13.135.227:8080/images/image20230224091502.png" title="image20230224091502.png" alt="image.png" style="max-width:100%"/></p>', 'description': '', 'execUserName': '宁逸铭', 'execUserId': 122, 'case_id': 43650, 'exec_type': '横向越权测试'}, '71383': {'execName': '会话清除测试不合规', 'bugId': 7690, 'image': '<p>登出后，数据包仍然可正常响应</p><p><img src="http://99.13.135.227:8080/images/image20230223145028.png" title="image20230223145028.png" alt="image.png" style="max-width:100%"/></p>', 'description': '', 'execUserName': '宁逸铭', 'execUserId': 122, 'case_id': 43656, 'exec_type': '会话清除测试'}, '71385': {'execName': '同一用户建立多个会话测试不合规', 'bugId': 7691, 'image': '<p>同一用户可同时登录并操作</p><p><img src="http://99.13.135.227:8080/images/image20230223145213.png" title="image20230223145213.png" alt="image.png" style="max-width:100%"/></p>', 'description': '', 'execUserName': '宁逸铭', 'execUserId': 122, 'case_id': 43657, 'exec_type': '同一用户建立多个会话测试'}, '71377': {'execName': '会话超时测试不合规', 'bugId': 7692, 'image': '<p>系统无超时登出机制，从2023/2/23上午11时开始闲置，2023/2/23下午2时恢复访问，系统仍处于登陆状态</p>', 'description': '', 'execUserName': '宁逸铭', 'execUserId': 122, 'case_id': 43654, 'exec_type': '会话超时测试'}, '71082': {'execName': 'HTTP响应头配置不合规', 'bugId': None, 'image': '<p>未配置Set-Cookie</p><p><img src="http://99.13.135.227:8080/images/image20230222172802.png" title="image20230222172802.png" alt="image.png" style="max-width:100%"/></p>', 'description': '', 'execUserName': '宁逸铭', 'execUserId': 122, 'case_id': 43658, 'exec_type': '安全配置'}, '71093': {'execName': '执行记录1', 'bugId': None, 'image': '<p>未配置X-Content-Type-Options</p><p><img src="http://99.13.135.227:8080/images/image20230222172957.png" title="image20230222172957.png" alt="image.png" style="max-width:100%"/></p>', 'description': 'HTTP响应头配置不合规', 'execUserName': '宁逸铭', 'execUserId': 122, 'case_id': 43662, 'exec_type': '安全配置'}, '71083': {'execName': '执行记录1', 'bugId': None, 'image': '<p>未配置Content-Security-Policy</p><p><img src="http://99.13.135.227:8080/images/image20230222172834.png" title="image20230222172834.png" alt="image.png" style="max-width:100%"/></p>', 'description': 'HTTP响应头配置不合规', 'execUserName': '宁逸铭', 'execUserId': 122, 'case_id': 43659, 'exec_type': '安全配置'}, '71094': {'execName': '执行记录1', 'bugId': None, 'image': '<p>未配置X-XSS-Protection</p><p><img src="http://99.13.135.227:8080/images/image20230222173024.png" title="image20230222173024.png" alt="image.png" style="max-width:100%"/></p>', 'description': 'HTTP响应头配置不合规', 'execUserName': '宁逸铭', 'execUserId': 122, 'case_id': 43663, 'exec_type': '安全配置'}, '71086': {'execName': '执行记录1', 'bugId': None, 'image': '<p>未配置X-Frame-Options</p><p><img src="http://99.13.135.227:8080/images/image20230222172858.png" title="image20230222172858.png" alt="image.png" style="max-width:100%"/></p>', 'description': 'HTTP响应头配置不合规', 'execUserName': '宁逸铭', 'execUserId': 122, 'case_id': 43660, 'exec_type': '安全配置'}, '71096': {'execName': '执行记录1', 'bugId': None, 'image': '<p>配置为*，不合规</p><p><img src="http://99.13.135.227:8080/images/image20230222173051.png" title="image20230222173051.png" alt="image.png" style="max-width:100%"/></p>', 'description': 'HTTP响应头配置不合规', 'execUserName': '宁逸铭', 'execUserId': 122, 'case_id': 43664, 'exec_type': '安全配置'}, '71089': {'execName': '执行记录1', 'bugId': None, 'image': '<p>未配置Strict-Transport-Security</p><p><img src="http://99.13.135.227:8080/images/image20230222172929.png" title="image20230222172929.png" alt="image.png" style="max-width:100%"/></p>', 'description': 'HTTP响应头配置不合规', 'execUserName': '宁逸铭', 'execUserId': 122, 'case_id': 43661, 'exec_type': '安全配置'}, '71057': {'execName': '跨链通讯查询参数存在SQL注入点', 'bugId': None, 'image': '<p>存在布尔盲注与时间盲注，经手工验证确认存在缺陷，sqlmap可继续获取数据库名、表名等信息</p><p><img src="http://99.13.135.227:8080/images/image20230227090743.png" title="image20230227090743.png" alt="image.png" style="max-width:100%"/></p><p><img src="http://99.13.135.227:8080/images/image20230227091259.png" title="image20230227091259.png" alt="image.png" style="max-width:100%"/></p><p><br/></p>', 'description': '', 'execUserName': '宁逸铭', 'execUserId': 122, 'case_id': 43628, 'exec_type': 'SQL注入测试'}, '71058': {'execName': '跨链交易查询参数存在SQL注入点', 'bugId': None, 'image': '<p>存在布尔盲注与时间盲注，经手工验证确认存在缺陷，sqlmap可继续获取数据库名、表名等信息</p><p><img src="http://99.13.135.227:8080/images/image20230227091337.png" title="image20230227091337.png" alt="image.png" style="max-width:100%"/></p><p><img src="http://99.13.135.227:8080/images/image20230227092136.png" title="image20230227092136.png" alt="image.png" style="max-width:100%"/></p><p><br/></p><p><br style="white-space: normal;"/></p><p><br/></p>', 'description': '', 'execUserName': '宁逸铭', 'execUserId': 122, 'case_id': 43629, 'exec_type': 'SQL注入测试'}, '71943': {'execName': '用户管理查询参数存在SQL注入点', 'bugId': None, 'image': '<p><img src="http://99.13.135.227:8080/images/image20230224160720.png" title="image20230224160720.png" alt="image.png" style="max-width:100%"/></p><p><img src="http://99.13.135.227:8080/images/image20230224160858.png" title="image20230224160858.png" alt="image.png" style="max-width:100%"/></p>', 'description': '存在布尔盲注与时间盲注，经手工验证确认存在缺陷，sqlmap可继续获取数据库名、表名等信息', 'execUserName': '宁逸铭', 'execUserId': 122, 'case_id': 43630, 'exec_type': 'SQL注入测试'}, '71022': {'execName': '链架构管理：下载配置文件可遍历下载', 'bugId': None, 'image': '<p>此功能点配置文件使用数字编号代替，可遍历下载配置文件</p><p><img src="http://99.13.135.227:8080/images/image20230222161721.png" title="image20230222161721.png" alt="image.png" style="max-width:100%"/></p>', 'description': '', 'execUserName': '宁逸铭', 'execUserId': 122, 'case_id': 43637, 'exec_type': '文件下载漏洞测试'}}
    res = sort_dict_by_desc(dd)
    print(res)

```

#### 0x02 日志
 
```python
# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2023/2/27 10:12
import logging
import colorlog


def get_logger(level=logging.INFO):
    # 创建logger对象
    logger = logging.getLogger()
    # 设置默认输出等级
    logger.setLevel(level)
    # 创建控制台日志处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    datefmt = '%Y-%m-%d %H:%M:%S'
    # 定义颜色输出格式
    color_formatter = colorlog.ColoredFormatter(
        '{log_color}{asctime} {levelname}:  {filename} {message}',
        datefmt=datefmt,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_black',
        },
        style='{'
    )
    # 将颜色输出格式添加到控制台日志处理器
    console_handler.setFormatter(color_formatter)
    # 移除默认的handler
    for handler in logger.handlers:
        logger.removeHandler(handler)
    # 将控制台日志处理器添加到logger对象
    logger.addHandler(console_handler)
    return logger


if __name__ == '__main__':
    logger = get_logger(logging.DEBUG)
    logger.debug('debug message')
    logger.info('info message')
    logger.warning('warning message')
    logger.error('error message')
    logger.critical('critical message')
```


#### 0x03 遍历
```python
a = [i for i in range(10)]
fun = lambda x : (2*x + x*x)
b = [ str(fun(i)) for i in a ]
''.join(b)
```

#### 0x04 加密
```python
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


if __name__ == '__main__':

    ...


```
#### 0x05 系统函数
```python
import os
# 1. 生成随机bytes
rand_bytes = os.urandom(10) 

# 2. 

```