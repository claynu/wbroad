import _thread
import json
import os
import re
import sqlite3

import mitmproxy.http
import yaml
from colorama import init

import decrypt_proxy as decrypt
from bin import sqli_api as api
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


init(autoreset=False)

config = yaml.safe_load(open('./global_config.yaml', 'r', encoding='utf-8'))
db_file = config['db_file']
target = config['target']
# sqli_flag = config['plugin']['sqlmapapi']['flag']


class interceptor(FileSystemEventHandler):
    def __init__(self, sqli_flag=None):
        init_sqlite()
        FileSystemEventHandler.__init__(self)
        self.load_config(False)
        self.sqli_scan_urls = []

    def on_modified(self, event):
        if "global_config.yaml" == event.src_path.split(os.sep)[-1]:
            try:
                self.load_config(True)
            except Exception as e:
                e.args


    def load_config(self,is_reload=True):
        global config,db_file,target
        config = yaml.safe_load(open('./global_config.yaml', 'r', encoding='utf-8'))
        db_file = config.get('db_file','')
        target = config.get('target')
        self.sqli_flag = config['plugin']['sqlmapapi']['flag']
        self.scan_url_unique = target.get('scan_url_unique',True)
        if not self.scan_url_unique:
            self.sqli_scan_urls = []
        self.scan_all_params = target.get('scan_all_params',False)
        init_sqlite()
        self.host = target['host']
        self.plugin = config['plugin']
        self.upstraem_proxy = config['mitm']['upstream_proxy']
        self.blacklist_url = target['blacklist']['url']
        self.sqli_flag = config['plugin']['sqlmapapi']['flag']
        self.blacklist_suffix = target['blacklist']['suffix'].split(',')
        if is_reload: printf(f'reload global_config',2)

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
            elif self.scan_all_params:
                if flow.request.method == 'POST' or '?' in flow.request.path:
                    sqli_scan_flag = True
            url = flow.request.url
            try:
                if url in self.blacklist_url or url.split('?')[0] in self.blacklist_url or \
                        url.split(".")[-1].split('?')[0] in self.blacklist_suffix:
                    printf(f'url {url} is in blacklist')
                    return
            except Exception as e:...

            if url not in self.sqli_scan_urls :
                if self.scan_url_unique:
                    self.sqli_scan_urls.append(url)
                _thread.start_new_thread(restore_req, (flow, sqli_scan_flag))

    def format_dict(self, path: str):
        res_dict = {}
        params = path.split('?')[-1].split('&')
        for param in params:
            key, value = param.split('=')
            res_dict[key] = value
        return res_dict

    def get_upstream(self):
        if self.upstraem_proxy:
            ip, port = self.upstraem_proxy.split('://')[-1].split(':')
            return (ip, int(port))
        if self.plugin['xray']['enable']:
            return ('127.0.0.1', self.plugin['xray']['port'])
        return ()


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
        UNIQUE("req")
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
    # 处理 mitmproxy host 没有端口 导致部分非默认端口请求sql扫描失败
    host = re.findall(r'https?://(.*?)/', url)
    host = flow.request.host if host == [] else host[0]
    req['headers']['Host'] = host
    if sqli_scan_flag:
        https_flag = False
        if flow.request.url.startswith('https'):
            https_flag = True
        api.sqli_detection(req, https_flag)
    try:
        sql = f"insert into request(url,req,path) values('{url}','{json.dumps(req, separators=(',', ':'))}','{path}')"
        # print(sql)
        cursor.execute(sql)
        printf(f'{url} 记录成功')
    except Exception as e:
        if e.args[0].find('UNIQUE') != -1:
            printf(f'{url}已存在')
        else:
            printf(f'restore_req insert error {e.args}')
    con.commit()

event = interceptor()
obs = Observer()
if not config['request_decoder']:
    addons = [
        event
    ]
else:
    addons = [
        decrypt.dec_proxy(config=config),
        event
    ]


obs.schedule(event,os.path.abspath('.'),recursive=True)
obs.start()

