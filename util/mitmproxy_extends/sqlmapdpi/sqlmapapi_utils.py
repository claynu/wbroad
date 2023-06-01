import getopt
import json
import requests
import string
import random
import sys
from colorama import init
from urllib import parse
init(autoreset=False)
import yaml

config = yaml.safe_load(open('global_config.yaml', 'r', encoding='utf-8'))
pre_url = config['plugin']['sqlmapapi']['url']


def printf(log, type=1):
    ''':type  1 red  2green  3 yellow  '''
    print(f'\033[3{type}m{log}\033[0m')


def get_result(user, project=''):
    url = f"{pre_url}/getTaskList"
    if project != '':
        url = f'{url}?project={parse.quote(project)}'
        printf(url)
    headers = {
        'Cookie': f'user={user}',
        'Content-Type': 'application/json',
    }
    response = requests.request("GET", url, headers=headers)
    if response.status_code != 200:
        print(f'获取扫描结果失败 {response.text}')
    return response.json()


def get_scan_detail(taskid=''):
    url = f"{pre_url}/getResult/{taskid}"
    headers = {
        'Content-Type': 'application/json',
    }
    response = requests.request("GET", url, headers=headers)
    if response.status_code != 200:
        print(f'获取扫描结果失败 {response.text}')
    return response.json()



def upload_file(file_path, user):
    url = f"{pre_url}/uploadeRequest"
    payload = {}
    files = [
        ('file',
         (''.join(random.choices(string.ascii_letters + string.digits, k=16)), open(file_path, 'rb'), 'text/plain'))
    ]
    headers = {
        'Cookie': f'user={user}'
    }
    response = requests.request("POST", url, headers=headers, data=payload, files=files)
    if response.status_code != 200:
        print(f'文件上传失败 {response.text}')
    return response.text


def createTasks(file_name, user, project):
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
    response = requests.request("POST", url, headers=headers, data=payload)
    return response.json()


if __name__ == '__main__':
    createTasks('test','heyu','test')