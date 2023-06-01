#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

# -* -coding: utf-8 -*-
# @File   :   flush_auth.py
# @Author :   RanPan
# @ModTime:   2023/1/10 14:33
# Description： sqlmap的tamper脚本，用于更新身份认证字段，避免失效

from lib.core.enums import PRIORITY
from lib.custom_plugins.auto_get_auth import get_code_by_itoidc
from lib.custom_plugins.auto_get_auth import get_code_by_itoidc_share_token

__priority__ = PRIORITY.HIGHEST

import os
import base64
import json
import time
import requests


def dependencies():
    pass


def tamper(payload, **kwargs):
    tmp_token = operate_file()
    # 获取headers
    headers = kwargs.get('headers', {})
    headers['Cookie'] = f'access_token_openapi={tmp_token}'
    return payload


def operate_file():
    # 临时存放身份信息
    file_path = './tamper/tmp_token.txt'
    if os.path.exists(file_path) is False:
        with open(file_path, 'w') as file:
            tmp_token = get_token()
            file.write(tmp_token)
    else:
        with open(file_path, 'r') as f:
            tmp_token = f.read()
            if len(tmp_token) <= 0 or is_flush(tmp_token):
                with open(file_path, 'w') as file:
                    tmp_token = get_token()
                    file.write(tmp_token)
    return tmp_token


def is_flush(token):
    # token过期时间小于半个小时就更新
    token = token.split('.')[1]
    missing_padding = 2 - len(token) % 2
    if missing_padding:
        token += '=' * missing_padding
    token = json.loads(base64.b64decode(token).decode("utf-8"))
    exp = token['exp']
    now = int(time.time())
    if exp - now < 3600 * 0.5:
        return True
    else:
        return False


def get_token():
    """
    根据待扫描系统的登录逻辑进行组合
    如OpenAPi对接的一号通，不能通过账密登录，但是可以利用一号通与ITOIDC的多源互认进行登录。
    1. 通过账密登录ITOIDC，获取share token；
    2. 利用share token从一号通获取登录的授权码code
    3. 再使用code，去OpenAPI的登录接口获取经其认证的token
    :return: token
    """
    share_token = get_code_by_itoidc(username='it009068', password='R087.anp', user_type='rtc')
    code = get_code_by_itoidc_share_token(client_id='e4f073cbfd6a4bcebb06bcdc4c51b588',
                                          redirect_uri='http://ops.openapi.paas.cmbchina.cn/ops/yhtLogin',
                                          share_token=share_token)
    token = get_open_api_token(code)
    return token


def get_open_api_token(code):
    """
    用code获取系统的身份认证，这一步需要根据第三方系统的登录逻辑自定义
    通过code获取OpenAPI市场的Token
    :param code: 授权码
    :return: token
    """
    openapi_url = "http://ops.openapi.paas.cmbchina.cn:80/ops/backend/user/v1/auth/yhtLogin"
    openapi_headers = {"Plat-Type": "ops", "Content-Type": "application/json;charset=UTF-8", "Connection": "close"}
    body_json = {"code": f"{code}"}
    token = requests.post(openapi_url, headers=openapi_headers, json=body_json).headers['Authorization'].replace(
        'Bearer ', '')
    return token

