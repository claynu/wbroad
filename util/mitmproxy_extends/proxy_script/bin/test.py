import json
import time
from urllib import parse

import requests
from colorama import init
import os
init(autoreset=False)
def printf(log,type=1):
    print(f'\033[3{type}m{log}\033[0m')

sqli_config={
    'url':"http://55.13.157.115:6000"

}

def get_result(user, project=''):
    url = sqli_config['url'] + "/getTaskList"
    if project != '':
        url = f'{url}?project={parse.quote(project)}'
    headers = {
        'Cookie': f'user={user}',
        'Content-Type': 'application/json',
    }
    response = requests.request("GET", url, headers=headers,proxies = {'http':"127.0.0.1:8080"})
    if response.status_code != 200:
        print(f'获取扫描结果失败 {response.text}')
    return response.json()


def get_scan_detail(taskid=''):
    url = sqli_config['url'] + f"/getResult/{taskid}"
    headers = {
        'Content-Type': 'application/json',
    }
    response = requests.request("GET", url, headers=headers,proxies = {'http':"127.0.0.1:8080"})
    if response.status_code != 200:
        print(f'获取扫描结果失败 {response.text}')
        return ''
    result = response.json()
    if result.get('result_detail', "") == '异常结束，请检查日志':
        log_url = sqli_config['url'] + f"/getLogs/{taskid}"
        logs = requests.request("GET", log_url, headers=headers,proxies = {'http':"127.0.0.1:8080"})
        result['logs'] = logs.text
    return result

if __name__ == '__main__':
    res = get_result('heyu','pbank')
    print(res)

    res2 = get_scan_detail('d441361068af5295')
    print(res2)
    sqli_config['url'] = 'http://127.0.0.1:8775'


    pre_url = 'http://127.0.0.1:8775'
    user = 'heyu'
    file_name = 'D:\TOOLS\工具\permission_check\version3\sqldet_file\lon_pbank-20221205-170706841818.txt'
    project = 'testtest'
    url = f"{pre_url}/createTasks"
    payload = json.dumps({
        "file": file_name,
        "project": project,
        "options": {
            "level": "3",
            "risk": "3",
            "threads": "5"
        }
    })
    printf(payload)
    headers = {
        'Cookie': f'user={user}',
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload,proxies = {'http':"127.0.0.1:8080"})
    print(response.text)

    sqli_config['url'] = 'http://127.0.0.1:8775'
    time.sleep(5)


    res2 = get_scan_detail(response.json()['0'])
    print(res2)

    res = get_result('heyu', 'testtest')
    print(res)





