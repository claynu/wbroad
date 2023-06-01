# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2022/10/27 10:12
import json

from colorama import init
import customer as enc_by_code

init(autoreset=False)
import yaml
import util
import re
import time

encrypt_enum = {
    "md5": "md5_encrypt",
    "base64": "base64_encode",
    "sm2": "sm2_encrypt",
    "aes": 'aes_encrypt',
    "aes-256-gcm": 'aes_encrypt'
}

## 约定
# path 包含 除协议域名外的信息 ： /index.html?a=1&b=2
# url 包含所有url信息 eg ： http[s]://host:port/path
# 获取请求头信息 headers.token headers.auth 通过.获取对应西悉尼
# 获取body信息  body.id,body.payload 等 如果是整个json则 body.json()   如果是json字符串则 body.text()#
# 如 明文格式为 b6565646465 为固定值
# GET: url=/index.php?a=1&b=2&body=b6565646465                    template: url={path}&body=b6565646465
# POST: url=/index.php?a=1&b=2&body="{"1":"asdasd"}"b6565646465   template: url={path}&body={body.json()}b6565646465

data_enum = {
    "{path}": "flow.request.path",
    "{timestamp_10}": "int(time.time())", #10 位
    "{timestamp_13}": "int(time.time()*1000)", #13 位
    "{url}": "flow.request.url",
    "{body.get_text}": "flow.request.get_text()",
    "{body.json}": "flow.request.json()",
    "{aad}": "self.aes_aad",
    "{iv}": "self.aes_iv",
    "{encrypt_text}": "encrypt_text",
    # "{encrypt_text}": "",
}



def parse_yaml_sign():
    config = yaml.safe_load(open('global_config.yaml', 'r', encoding='utf-8'))
    cust = config["customer"]
    sign = cust.get('sign', {})
    if sign != {}:
        encry = sign.get('encry', "").lower()
        if encry not in encrypt_enum.keys(): return None


class req():
    def __init__(self, method='GET'):
        self.headers = {'token': "test_token"}
        self.method = method
        self.path = '/index.html?a=1'
        self.url = 'http://www.baidu.com/index.html?a=1'
        self.host = 'www.baidu.com'
        self.text = '''{'test_body':'1','id':'121'}'''
        self.body = '''{'test_body':'1','id':'121'}'''

    def get_text(self):
        return self.text

    def set_text(self,text):
        self.text = text

    def json(self):
        return eval(self.text)


class http():
    def __init__(self, method):
        self.request = req(method)


class customer_by_config():

    def __init__(self,config:dict):
        customer = config['customer']
        code_or_config = customer['code_or_config']
        # 签名配置信息
        sign_config = config['customer']["sign"]
        self.flag = sign_config['flag']
        self.key = bytes.fromhex('01' * 32)
        self.methods = sign_config['method']
        self.value_pos = sign_config['value_pos'].split('.')
        self.algorithm = getattr(util, encrypt_enum[sign_config['algorithm']])
        self.white_list_path = customer.get('white_list_path',[])
        # 加密配置信息
        encrypt_config = config['customer']["encrypt"]
        self.enc_algorithm = getattr(util, encrypt_enum[encrypt_config['algorithm']])
        self.enc_methods = encrypt_config['method']
        self.enc_keyword = encrypt_config['keyword']  # 加密相关信息
        self.aes_iv = encrypt_config['keyword']['aes-gcm'].get('iv','')
        self.aes_aad = encrypt_config['keyword']['aes-gcm'].get('aad','')
        self.enc_methods = encrypt_config['method']
        self.format_encrypt_text = encrypt_config['format_encrypt_text']

        if code_or_config == 'code':
            self.sign = getattr(enc_by_code,'sign')
            self.encrypt = getattr(enc_by_code,'encrypt')
            self.decrypt = getattr(enc_by_code,'decrypt')
        if code_or_config == '' or code_or_config is None or code_or_config == 'none':
            self.sign =  self.empty
            self.encrypt =  self.empty
            self.decrypt =  self.empty
    def get_aad(self):
        return self.aes_aad

    def get_iv(self):
        return self.aes_iv

    def empty(self,flow):
        pass
        # self.template =  sign_config['method'].get(flow.request.method, '')  # 字典

    def format_template(self, flow, template):
        if template == '' or template is None:
            return
        values = re.findall("\{.*?\}", template)
        print(values)
        for value in values:
            template = template.replace(value, eval(data_enum[value]))
        return template



    def sign(self, flow):
        if flow.request.method in self.methods.keys() and flow.request.path.split('?')[0] not in self.white_list_path :
            text = self.format_template(flow, self.methods[flow.request.method])
            print(f'格式处理后明文为 = {text}')
            if self.value_pos[0] == 'headers':
                flow.request.headers[self.value_pos[1]] = self.algorithm(text)
            if self.value_pos[0] == 'body':
                body = flow.request.body()
                body[self.value_pos[1]] = self.algorithm(text)
                flow.request.set_text(json.dumps(body, separators=(",", ":")))
        print(text)
        return flow

    def encrypt(self, flow):
        if flow.request.method in self.methods.keys() and flow.request.path.split('?')[0] not in self.white_list_path:
            text = self.format_template(flow, self.enc_methods.get(flow.request.method,''))
            encrypt_text = self.enc_algorithm(key=self.key,data=text)
            print(encrypt_text)
            # template = self.format_encrypt_text
            # template = template.replace('{encrypt_text}',encrypt_text)
            flow.request.set_text(json.dumps(encrypt_text))
        return flow


if __name__ == '__main__':
    flow = http('POST')
    print(flow.request.text)
    print(flow.request.headers)
    config = yaml.safe_load(open('../global_config.yaml', 'r', encoding='utf-8'))
    cust = customer_by_config(config)
    cust.encrypt(flow)
    cust.sign(flow)

    print(flow.request.text)
    print(flow.request.headers)
