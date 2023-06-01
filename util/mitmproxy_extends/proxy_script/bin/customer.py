# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2022/10/26 14:06
# describe: **基于业务的加密加签功能**
import datetime
import json
import os

import mitmproxy.http

import util as util


def sign(flow: mitmproxy.http.HTTPFlow,**kwargs):
    """ todo 签名方法
    :param flow:  http 流
    :return:  flow
    url       ->  flow.request.url        'http://xxx.com/a/b?asd'
    path       ->  flow.request.path        '/a/b?asd'
    headers   ->  flow.request.headers    MultiDict({'cookie':'123','sign':'asdasd'})  获取方式 headers['sign']
    body      ->  flow.request.get_text()     文本格式
    body (json格式)     ->  flow.request.json() 如果非json格式会报错
    url flow.request.host -> host
    """
    path = flow.request.path
    if path.startswith('/ocm'):
        return sign_whit_sha256(flow)
    g = "j9da6fld2khgz2chd354czbfd2b2fs3ea"
    path = format_get_params(path)
    encode_data = f"url={path}&body={g}"
    if flow.request.method == 'POST':
        body = flow.request.json()
        if body.get('payload', '') != '':
            return flow
        encode_data = f"url={path}&body={json.dumps(body, separators=(',', ':'))}{g}"
    # encode_data = encode_data.replace('ibank-pbanking-asoc', 'ibank-pbanking')
    flow.request.headers['Sign'] = util.md5_encrypt(encode_data)
    print(flow.request.headers['Sign'])
    return flow

def sign_whit_sha256(flow: mitmproxy.http.HTTPFlow):
    g = "czl42bk4ocm682czg2vrs3elq6cas9qfd"
    path = flow.request.path
    if path.find("params") != -1:
        # 不加签
        return
    url_params = json.loads(path.split('?')[-1])
    encode_data = f"url={path}?{'&'.join([f'{i}={url_params[i]}' for i in sorted(url_params)])}&body=czl42bk4ocm682czg2vrs3elq6cas9qfd"
    if flow.request.method == 'POST':
        body = flow.request.json()
        if body.get('payload', '') != '':
            return flow
        encode_data = f"url={path}&body={json.dumps(body, separators=(',', ':'))}{g}"
    # encode_data = encode_data.replace('ibank-pbanking-asoc', 'ibank-pbanking')
    flow.request.headers['Sign'] = util.sha256(encode_data.encode())
    return flow


def encrypt(flow: mitmproxy.http.HTTPFlow,key=bytes.fromhex('05' * 32)):
    """
    todo 请求加密方法 加密后需要更新flow中的对应数据
    :param flow:  http 流
    :return:  flow
    url       ->  flow.request.url        'http://xxx.com/a/b?asd'
    path       ->  flow.request.path        '/a/b?asd'
    headers   ->  flow.request.headers    MultiDict({'cookie':'123','sign':'asdasd'})  获取方式 headers['sign']
    body      ->  flow.request.get_text()     文本格式
    body (json格式)     ->  flow.request.json() 如果非json格式会报错
    url flow.request.host -> host
    """
    # 部分请求和get不需要加密 在此做白名单处理
    if flow.request.path in ["/ibank-channel/route/keyAgreement",
                             "/ibank-pbanking-asoc/userManage/getAccountInfo",
                             "/ibank-pbanking-asoc/notice/sendAppVeryCode"] or flow.request.method != 'POST' or flow.request.get_text().find(
        'payload') != -1:
        return flow
    data = json.dumps(flow.request.json(), separators=(',', ':'))
    aad = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    iv = os.urandom(12)
    # key = bytes.fromhex('05' * 32)
    crypt_text = util.aes_encrypt(key, iv, aad, data)
    format_data = {
        'payload': crypt_text,
        'aad': aad,
        'iv': util.base64_encode(iv)
    }
    print(json.dumps(format_data, separators=(',', ':')))
    flow.request.set_text(json.dumps(format_data, separators=(',', ':')))
    return flow


def decrypt(response: str, key=bytes.fromhex('05' * 32)):
    """
    todo 响应解密方法 主要是repeater中解密响应用
    :param response: text 的 http 响应
    :return:  text
    """
    res = json.loads(response)
    result = response
    if 'aad' in res.keys() and 'iv' in res.keys():
        aad = res['aad']
        iv = util.base64_decode(res['iv'])
        print(res.get('encrypt', res.get('payload', '')))
        result = util.aes_decrypt(key, iv, aad, res.get('encrypt', res.get('payload', '')))
    return result


# 其他需要自定义方法
def format_get_params(path):
    """
    格式化处理请求的参数 用于本项目中的签名
    :param path:
    :return:
    """
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


if __name__ == '__main__':
    res = decrypt(json.dumps({
                                 "payload": "vtxCOjH/jQtyXzxBAW/TXC28I0Amvwj4FuRmnG1CdHTfDUBMNE7p9Bwt560rE8Yq0tx1/myOdWM6lrGFDfvkmbCKw52IvsI7z+ayXVmUxgTt9ozwTCRman2VZ9qVkW49i4ghPcAHyIZxTeyTzCEj+bBPIqJH1uCu81M7FhdWK8E199tME1P2h4fwrg==",
                                 "iv": "pBvXnfY2tkqAPTZJ", "aad": "2022-11-23 08:53:51"}))
    print(res)
