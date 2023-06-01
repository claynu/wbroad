# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2022/10/26 15:39

import datetime
import os
from urllib import parse

import requests
import yaml
from colorama import init
init(autoreset=False)

def printf(log, type=1):
    print(f'\033[3{type}m{log}\033[0m')


config = yaml.safe_load(open('global_config.yaml', 'r', encoding='utf-8'))
target = config['target']
sqli_config = config['plugin']['sqlmapapi']
project = sqli_config['project']
proxies = sqli_config.get('proxies',None)
timeout = sqli_config.get('timeout',5)



def save_req(req):
    path = './sqldet_file/'
    file_name = f'{project}-{datetime.datetime.now().strftime("%Y%m%d-%H%M%S%f")}.txt'
    f = open(path + file_name, 'a+', encoding='utf-8')
    raw_str = f"{req['method']} {req['url']} HTTP/1.1\n"
    for header in req['headers'].keys():
        raw_str += f'{header}: {req["headers"][header]}\n'
    if req['body']:
        raw_str += f'\n{req["body"]}'
    else:
        raw_str += '\n\n'
    f.write(raw_str)
    f.close()

    return file_name


def upload(req: dict):
    path = './sqldet_file/'
    file_name = save_req(req)
    url = sqli_config['url'] + "/uploadeRequest"
    if sqli_config['url'].find('127.0.0.1') != -1:
        print(os.path.abspath('.') + os.sep + 'sqldet_file' + os.sep + file_name)
        return os.path.abspath('.') + os.sep + 'sqldet_file' + os.sep + file_name
    payload = {}
    files = [
        ('file', (file_name, open(path + file_name, 'rb'), 'text/plain'))
    ]
    headers = {
        'Cookie': f'user={sqli_config["user"]}'
    }
    response = requests.request("POST", url, headers=headers, data=payload, files=files,proxies=proxies,verify=False,timeout=4)
    fileName = response.text
    if "fileName" in  response.text:
        fileName = response.json()['fileName']
    print(f'新增 sqli 扫描任务 url={req["url"]}',2)
    return fileName


def sqli_detection(req, https_flag=False,times=0):
    filename = upload(req)
    url = sqli_config['url'] + '/createTasks'
    headers = {
        'Cookie': f'user={sqli_config["user"]}',
        'Content-Type': 'application/json'
    }
    payload = {
        "file": filename,
        "project": project,
        "options": sqli_config['options']
    }
    if https_flag:
        payload['options']['forceSSL'] = True
    response = requests.request("POST", url, headers=headers, json=payload,proxies=proxies,verify=False,timeout=4)
    if response.status_code != 200:
        if times == 0:
            printf(f'sqlmapapi 新增扫描任务异常 重试1次 状态码{response.status_code} {response.text} ', 1)
            return sqli_detection(req, https_flag, times+1)
        else:
            printf(f'sqlmapapi 新增扫描任务异常 联系冉攀！！ 状态码{response.status_code} {response.text} ', 1)
    return response.status_code


def get_result(user, project=''):
    url = sqli_config['url'] + "/getTaskList"
    if project != '':
        url = f'{url}?project={parse.quote(project)}'
    headers = {
        'Cookie': f'user={user}',
        'Content-Type': 'application/json',
    }
    response = requests.request("GET", url, headers=headers,proxies=proxies,verify=False,timeout=4)
    if response.status_code != 200:
        print(f'获取扫描结果失败 {response.text}')
    return response.json()


def get_scan_detail(taskid=''):
    url = sqli_config['url'] + f"/getResult/{taskid}"
    headers = {
        'Content-Type': 'application/json',
    }
    response = requests.request("GET", url, headers=headers,proxies=proxies,verify=False,timeout=4)
    if response.status_code != 200:
        result = {'detail':"异常结束，请检查日志"}
    else:
        result = response.json()
    if result.get('detail', "") == '异常结束，请检查日志':
        log_url = sqli_config['url'] + f"/getLogs/{taskid}"
        # logs = requests.request("GET", log_url, headers=headers)
        result['log_url'] = log_url
    return result


# if __name__ == '__main__':
#     res = get_result(user='XL', project='pe-acs2')
#     print(res)
#     print(res['0']['result_detail'])
#     print(res['0']['result_detail'] == '异常结束，请检查日志')
