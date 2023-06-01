# -* -coding: utf-8 -*-
# @File   :   auto_get_auth.py
# @Author :   RanPan
# @ModTime:   2023/1/13 16:50
# Description：

import re
import requests
import datetime

"""
Usage::
    根据待登录的第三方系统的登录逻辑进行组合
    目前支持：一号通自动登录（session）、ITOIDC自动登录(session/账密)、多源互认自动登录（对接一号通的系统通过ITOIDC登录）、接码平台自动登录（通知系统自助管理平台）
example:
    如OpenAPi对接的一号通，不能通过账密登录，但是可以利用一号通与ITOIDC的多源互认进行登录。
    1. 通过账密登录ITOIDC，获取share token；
    2. 利用share token从一号通获取登录的授权码code
    3. 再使用code，去OpenAPI的登录接口获取经其认证的token

    share_token = get_code_by_itoidc(username='it009068', password='password', user_type='rtc')
    code = get_code_by_itoidc_share_token(client_id='e4f073cbfd6a4bcebb06bcdc4c51b588',
                                          redirect_uri='http://ops.openapi.paas.cmbchina.cn/ops/yhtLogin',
                                          share_token=share_token)
    token = get_open_api_token(code)

    def get_open_api_token(code):
        openapi_url = "http://ops.openapi.paas.cmbchina.cn:80/ops/backend/user/v1/auth/yhtLogin"
        openapi_headers = {"Plat-Type": "ops", "Content-Type": "application/json;charset=UTF-8", "Connection": "close"}
        body_json = {"code": f"{code}"}
        token = requests.post(openapi_url, headers=openapi_headers, json=body_json).headers['Authorization'].replace(
            'Bearer ', '')
        return token
"""


def get_code_by_oa_auth(client_id, redirect_uri, auth_session_id):
    """
    通过auth_session_id从一号通获取code，需通过抓包或浏览器查看auth_session_id
    auth_session_id 有效期短，推荐优先通过ITOIDC账密的形式获取code
    :param client_id: 第三方系统在一号通注册的id
    :param redirect_uri: 第三方系统在一号通注册的跳转地址
    :param auth_session_id: 一号通登录后的auth_session_id
    :return: code
    """
    oa_auth_url = f'https://oa-auth.paas.cmbchina.com/auth-server/login/auth?clientId={client_id}&redirectUri={redirect_uri}&state=&enterpriseId=&virtualUserId=&_='
    auth_session_id = {"auth_session_id": f"{auth_session_id}"}
    location = requests.get(oa_auth_url, cookies=auth_session_id, allow_redirects=False).headers['Location']
    if location.find('response_type') != -1:
        print('auth_session_id已失效')
    else:
        code = location.split('code=')[1]
        return code


def get_code_by_itoidc(username, password, user_type='rtc', client_id=None, redirect_uri=None):
    """
    通过ITOIDC密码登录，直接获取对接ITOIDC的系统授权码code，如果是对接一号通的系统则可以使用同源互认的原理换取share_token获取授权码code
    :param username: ITOIDC的用户名
    :param password: ITOIDC的密码
    :param user_type: rtc/itc
    :param client_id: 第三方系统在ITOIDC注册的id
    :param redirect_uri: 第三方系统在ITOIDC注册的跳转地址
    :return: code/share_token
    """
    # 密码登录ITOIDC
    # 第一步
    itoidc_login_url_1 = "https://oidc.idc.cmbchina.cn:443/login?"
    login_headers_1 = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "X-User-Type": "rtc"}
    login_data_1 = {"username": username, "password": password, "user_type": user_type, "data": '', "token": '',
                    "verify_code": "123456", "mfa": "false"}
    response = requests.post(itoidc_login_url_1, headers=login_headers_1, data=login_data_1)
    itoidc_session = response.headers['Set-Cookie'].split(';')[0]
    # 第二步
    itoidc_login_url_2 = "https://oidc.idc.cmbchina.cn:443/login"
    login_headers_2 = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                       "Cookie": f"{itoidc_session}"}
    login_data_2 = {"username": username, "password": password, "user_type": user_type,
                    "verify_code": '', "mfa": "true"}
    response = requests.post(itoidc_login_url_2, headers=login_headers_2, data=login_data_2)
    itoidc_session = {response.headers['Set-Cookie'].split(';')[0].split('=')[0]:
                          response.headers['Set-Cookie'].split(';')[0].split('=')[1]}
    share_token = response.json()['maJwt']

    if client_id is not None and redirect_uri is not None:
        # 如果有client_id和redirect_uri则表示第三方系统为对接ITOIDC的系统，直接获取code
        get_code_url = f'https://oidc.idc.cmbchina.cn/authorize??userType=yst-qr+itc+rtc+srm+native&mfa=false&client_id={client_id}&redirect_uri={redirect_uri}&response_type=code'
        location = requests.get(get_code_url, cookies=itoidc_session, allow_redirects=False).headers['Location']
        code = re.findall('code=([a-zA-Z0-9]+)', location)
        return code
    else:
        return share_token


def get_code_by_itoidc_share_token(client_id, redirect_uri, share_token) -> str:
    """
    对接一号通的第三方系统，但是可以通过ITOIDC的share_token实现免登录
    :param client_id: 第三方系统在一号通注册的id
    :param redirect_uri: 第三方系统在一号通注册的跳转地址
    :param share_token: ITOIDC登录后获取
    :return: code
    """
    # 获取auth_session_id
    get_auth_session_id_url = f'https://oa-auth.paas.cmbchina.com/auth-server/login/auth?clientId={client_id}&redirectUri={redirect_uri}&state=&enterpriseId=&virtualUserId=&_='
    auth_session_id = requests.get(get_auth_session_id_url).headers['Set-Cookie'].split(';')[0].split('=')[1]
    oa_auth_share_url = "https://oa-auth.paas.cmbchina.com:443/auth-server/login/authShare"
    oa_auth_share_cookies = {"auth_session_id": f"{auth_session_id}"}
    oa_auth_share_headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
    oa_auth_share_data = {"clientId": f"{client_id}",
                          "token": f"{share_token}"}
    code = requests.post(oa_auth_share_url, headers=oa_auth_share_headers, cookies=oa_auth_share_cookies,
                         data=oa_auth_share_data).json()['data']['redirectUri'].split('code=')[1]
    return code


def get_phone_code(phone_num, environment='ST', channel='短信'):
    """
    通过通知系统自助管理平台获取手机验证码
    :param phone_num:
    :param environment: ST/UAT
    :param channel: 短信、邮件、微信、APP
    :return:
    """
    token = 'eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJydGNfaWQiOiJJVDAwOTA2OCIsInN1YiI6IklUMDA5MDY4QGN3Iiwib19pcCI6Ijk5LjE1LjE1Ni4xNjkiLCJ5c3RfaWQiOiJBQUZBVFMiLCJvcmlnaW4iOiJvYSIsImtpZCI6InJzYTEiLCJpc3MiOiJodHRwczpcL1wvb2lkYy5pZGMuY21iY2hpbmEuY25cLyIsImN3X2lkIjoiSVQwMDkwNjgiLCJkZXAiOiIiLCJzYXBfaWQiOiJJVDAwOTA2OCIsImF1ZCI6ImxmMjdfbm90aWZ5IiwidXNlcl90eXBlIjoieXN0Iiwib2ZmaWNlX3RlbCI6IiIsImF1dGhfdGltZSI6MTY3MjcwNjQyNiwibmFtZSI6IuWGieaUgCIsInBob25lX251bWJlciI6IjE3Nzk2NDE4MjY1IiwiZXhwIjoxNjcyNzIwODI3LCJpYXQiOjE2NzI3MDY0MjcsImp0aSI6IjczNTRlM2ViLTcwNWQtNGVjNy1iZDEzLWMxZjNlOGUzYmFhZCIsImVtYWlsIjoicmFucDAwOTA2OEBvZGMuY21iY2hpbmEuY24iLCJhdXRoX2ZhY3RvciI6WyJxckNvZGUiXSwidXNlcm5hbWUiOiJBQUZBVFMifQ.U_SDVV5DM_y9SbfpZ7VeEEUvgn3qIvAi0oRMXE34YfXEfZBjrxVjqdWtmwd8JhIMf82pj2VBBuuRb-vjOS5WKw1uOmFHbRj2D2rK8s8cxhxQ0M0HIxN2JOsBCkwLDThpI_q3B8ESsvYNtuxozJSA20UgMRjpyULgmPFbsj49DB7snSYPNejkPGc0jDdkwxBpB6KKquXA4y1B2mbgAZA1VEMnh-1H9oX3ijMOHS_sH2eNRNaY5t8Xos8ZNeQvF1P_RNyt_GmPccQpMEtfVgP41IeVK7ooAFIFPSbHJE1aELKba0TepecsuRHWqJzwP7FbjWXb4VOJofGU3unl2SHoSw'
    environment = environment.upper()
    time_now = datetime.datetime.now().strftime('%Y-%m-%d')
    url = f'http://notification.paasuat.cmbchina.cn:80/{environment}/message?beginDate={time_now}&endDate={time_now}&database=currentBase&addr={phone_num}&username=IT009068&channel=%E7%9F%AD%E4%BF%A1&sessionId=&pageIndex=1&pageSize=10&page4Index=1&page4Size=10'
    headers = {
        'Authorization': token
    }

    response = requests.get(url, headers=headers).json()
    if response['status'] == 0 and len(response['data']['data']) > 0:
        session_id = response['data']['data'][0]['sessionId']
        msg_num = response['data']['data'][0]['msgNo']
    elif response['status'] == 0 and len(response['data']['data']) == 0:
        return '\n' + f'{phone_num} - 当前无验证码' + '\n'

    url = f'http://notification.paasuat.cmbchina.cn/{environment}/message/detail?sessionId={session_id}&msgNo={msg_num}&channel={channel}'
    response = requests.get(url, headers=headers).json()
    if response['status'] == 0:
        return response['data']['msgBody']
    else:
        return response['msg']
