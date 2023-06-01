# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2023/2/17 9:43
import requests


def get_code(phone,url='http://webconsole.paasst.cmbchina.cn/code/getyzm',type='uat'):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0',
        'Accept': '*/*',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    }
    data = {
        'type': type,
    }
    response = requests.post(url, headers=headers, data=data)
    for d in response.json():
        if 'skt' in url:
            res_phone = d.get("USR_UID","")
        else:
            res_phone = d.get("USR_MPH","")
        if res_phone == phone:
            return d['SND_TIM'],d['PIN_COD']
    return None, None

urls = {
    'yjf':'http://webconsole.paasst.cmbchina.cn/code/getyzm',
    'skt':'http://webconsole.paasst.cmbchina.cn/code/getskt'
}

if __name__ == '__main__':

    phone = '18800730002'   # 接收验证码手机号
    type = 'yjf'           # yjf 云缴费 skt 收款通
    # type = 'skt'            # yjf 云缴费 skt 收款通
    env = 'uat'              # 环境  uat st
    SND_TIM = None          # 去重
    while 1:
        snd_time, code = get_code(phone,urls[type],env.lower() )
        if SND_TIM != snd_time and snd_time is not None:
            SND_TIM = snd_time
            print(f'{phone} 验证码 {code} 接收时间 {snd_time}')
