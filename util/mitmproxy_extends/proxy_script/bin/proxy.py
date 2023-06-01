import _thread
import json
import operator
import re
import sqlite3

import mitmproxy.http
import yaml
from colorama import init

import customer as cust
import sqli_api as api
import util

config = yaml.safe_load(open('./global_config.yaml', 'r', encoding='utf-8'))
db_file = config['db_file']
sqli_flag = config['plugin']['sqlmapapi']['flag']


class interceptor:

    def __init__(self, sqli_flag):
        target = config['target']
        self.custom = cust

        init_sqlite()
        self.rsa_key = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjJfOU11YxUQNGzNmuqcNshlwFoHgqeZxxn99MaTf/AkwWQg52M7BMDC8XKxMgRraNBf69vPBog3t2v1bHoIvo8DALJxck7jBG4tO44GXo2lQiaKbvjeSMz0qSaD23pLhS3Q1vfxBP2excTbR3IoLP34dDXksy3zkWoBTnB3uEV7G59H36nKX80KbABBbepd02iWd40F8qTNNrxNYk/2FDz6SzITRwZzi4dTqFiV/RMNpL3oxF62/Ubcw53Cmpj4xXg0bgaoGh1t6rtYg7ww4kX4SdrjcT4s4REkpmeR/g3O6H/AlHYddvnzz8we33BP6BnvljErV2zbYAe8u+0Lb1QIDAQAB'
        self.aes_key = '9oMGYugTGRON5EsZuLBXpKeSfbKleg94'
        self.key = bytes.fromhex('01' * 32)
        self.host = target['host']
        self.plugin = config['plugin']
        self.upstraem_proxy = config['mitm']['upstream_proxy']
        self.sign = config['mitm']['request']['sign']
        self.encrypt = config['mitm']['request']['encrypt']
        self.decrypt = config['mitm']['response']['decrypt']
        self.blacklist_url = target['blacklist']['url']
        self.sqli_flag = sqli_flag
        self.blacklist_suffix = target['blacklist']['suffix'].split(',')

    def match_host(self, host):
        if isinstance(self.host, list):
            return host in self.host
        return host == self.host or re.match(self.host,
                                             host) is not None

    def request(self, flow: mitmproxy.http.HTTPFlow):
        sqli_scan_flag = False
        if self.match_host(flow.request.host):
            if flow.request.url.find(self.sqli_flag) != -1:
                flow.request.url = flow.request.url.replace(self.sqli_flag, '')
                sqli_scan_flag = True
            url = flow.request.url
            if url in self.blacklist_url or url.split(".")[-1].split('?')[0] in self.blacklist_suffix:
                printf(f'url {url} is in blacklist')
                return
            ordered_list = sorted(config['mitm']['request'].items(), key=operator.itemgetter(1), reverse=True)
            ## TODO DELETE START
            path = flow.request.path
            if path.startswith('/ocm'):
                if path.find('params') != -1:
                    # 解密
                    printf(f"{self.aes_key},{path.split('params=')[-1]}",2)
                    printf(f"ase key = {self.aes_key}",2)
                    params = util.aes_ecb_decrypt(self.aes_key,util.url_decode(path.split('params=')[-1]))
                    printf(f'{params}',2)
                    # printf(f"url={path}?{'&'.join([f'{i}={params[i]}' for i in sorted(params)])}",2)
                    return
                elif path.find('?') == -1:
                    return
                else:
                    # sign
                    # cust.sign_whit_sha256(flow)
                    # url_params = json.loads(path.split('?')[-1])
                    # encode_data = f"url={path.split('?')[0]}?{'&'.join([f'{i}={url_params[i]}' for i in sorted(url_params)])}&body=czl42bk4ocm682czg2vrs3elq6cas9qfd"
                    encode_data = f"url={path}&body=czl42bk4ocm682czg2vrs3elq6cas9qfd"
                    printf(encode_data,2)
                    flow.request.headers['Sign'] = util.sha256(encode_data.encode())
                    flow.request.headers['aeskey'] = util.rsa_encrypt(self.rsa_key,self.aes_key)
                    # enc_params = path.split('?')[-1]
                    enc_params =self.format_dict(path)
                    enc_params = util.aes_ecb_encrypt(self.aes_key,json.dumps(enc_params,separators=(',',':')))
                    printf(f'key={self.aes_key}\ndata={util.url_encode(enc_params)}',2)
                    flow.request.path = path.split('?')[0] + f'?params={util.url_encode(enc_params)}'
                return
            #### END
            if config['mitm']['show_origin_requet'] > 0 and flow.request.get_text():
                origin_test = self.custom.decrypt(flow.request.get_text(), key=self.key)
                printf(f'请求原文为{origin_test}', 2)
            # todo 调用配置生产的代码还是自定义的代码

            for item in ordered_list:
                print(item)
                if item[1] > 0:
                    flow = getattr(self.custom, item[0])(flow, key=self.key)  # 反射调用加密加签
            _thread.start_new_thread(restore_req, (flow, sqli_scan_flag))

    def format_dict(self, path:str):
        res_dict = {}
        params = path.split('?')[-1].split('&')
        for param in params:
            key,value = param.split('=')
            res_dict[key] = value
        return res_dict

    def response(self, flow: mitmproxy.http.HTTPFlow):
        try:
            try:
                # printf(f'resp = {flow.response.get_text()}',2)
                text = util.aes_ecb_decrypt(self.aes_key,flow.response.get_text())
                # printf(f'resp = {text}',2)
                flow.response.set_text(text)
            except Exception as e:
                print(e.args)
                pass
            try:
                res = flow.response.json()
                printf(f'{res}',2)
                if "publicKey" in res.keys():
                    self.rsa_key = res.get('publicKey','')
                    printf(f'self.rsa_key = {self.rsa_key }',2)
                if "data" in res.keys() and "pubKey" in res.get("data",{}).keys():
                    key_bytes = res.get("data",{}).get("pubKey",'1')
                    self.key = bytes.fromhex(f'0{key_bytes}' * 32)

            except Exception as e:
                pass
            if self.decrypt <= 0:
                return
            encrypt_text = json.dumps(flow.response.json(), separators=(',', ':'))
            if encrypt_text.find('encrypt') != -1:
                # todo 解密
                try:
                    text = self.custom.decrypt(encrypt_text)
                except Exception as e:
                    text = self.custom.decrypt(encrypt_text, key=bytes.fromhex('01' * 32))
                flow.response.set_text(text)
        except json.JSONDecodeError:
            pass

    def get_upstream(self):
        if self.upstraem_proxy:
            ip, port = self.upstraem_proxy.split('://')[-1].split(':')
            return (ip, int(port))
        if self.plugin['xray']['enable']:
            return ('127.0.0.1', self.plugin['xray']['port'])
        return ()


init(autoreset=False)


# db_file = yaml.safe_load(open('./global_config.yaml', 'r', encoding='utf-8'))['db_file']


def printf(log, type=1):
    print(f'\033[3{type}m{log}\033[0m')


def init_sqlite():
    """
    初始化 sqlite 数据库
    :return:
    """
    global db_file
    con = sqlite3.connect(db_file)
    init_sql = '''CREATE TABLE if not exists `request` (
    	`id`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    	`url`	TEXT NOT NULL,
    	`req`	TEXT NOT NULL,
    	`path`	TEXT NOT NULL,
    	`remark`    TEXT,
        UNIQUE("path")
    );
    '''
    con.execute("pragma encoding='UTF-8'")
    con.execute(init_sql)
    con.commit()
    con.close()


def con_sqlite():
    global db_file
    return sqlite3.connect(db_file)


def restore_req(flow: mitmproxy.http.HTTPFlow, sqli_scan_flag=False):
    """
    保存请求到sqlite，需要sql扫描的发送到sqlmapapi
    :param flow:
    :param sqli_scan_flag:
    :return:
    """
    con = con_sqlite()
    cursor = con.cursor()
    url = flow.request.url
    path = url.split('?')[0]
    req = {
        'url': flow.request.path,
        'method': flow.request.method,
        'headers': dict(flow.request.headers),
        'body': flow.request.get_text()
    }
    req['headers']['Host'] = flow.request.host
    if sqli_scan_flag:
        https_flag = False
        printf(f'sql 扫描任务{req}')
        if flow.request.url.startswith('https'):
            https_flag = True
        api.sqli_detection(req, https_flag)
    try:
        sql = f"insert into request(url,req,path) values('{url}','{json.dumps(req, separators=(',', ':'))}','{path}')"
        cursor.execute(sql)

    except Exception as e:
        if e.args[0].find('UNIQUE') != -1:
            printf(f'本记录已存在 {e.args}')
        else:
            printf(f'restore_req insert error {e.args}')
    con.commit()


addons = [
    interceptor(sqli_flag=sqli_flag)
]

