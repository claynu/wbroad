# 定时重放去请求token默认为高权限账户
# 配合xray 默认对所有参数进行sql扫描
import json
import math
import sqlite3
import threading
import time

import requests
import yaml
from colorama import init

import sqli_api as api

init(autoreset=False)
config = yaml.safe_load(open('./global_config.yaml', 'r', encoding='utf-8'))
db_file = config['db_file']
sqlite_write_lock = threading.Lock()
scan_url = []

def con_sqlite():
    global db_file
    return sqlite3.connect(db_file)


def get_all_records():
    con = con_sqlite()
    cursor = con.cursor()
    sql = 'select id,url, req from request'
    cursor.execute(sql)
    res = cursor.fetchall()
    return res


def printf(log, type=1):
    print(f'\033[3{type}m{log}\033[0m')


def merge_header(origin, modify):
    for key in modify.keys():
        origin[key] = modify[key]
    return origin


def repeater(record: tuple, auth_dict: dict, det_methods=[],sql_det_status=True):
    """
    重放请求
    :param record:  sqlite 中取出的请求 (id, req)
    :param auth_dict:  认证信息  {'upper_permission': {'token': 'eyJ0eXAiOiJKV1QiLC'}}
    :return: none
    """
    global sqlite_write_lock
    for auth_type in auth_dict:
        try:
            id, url, req = record

            req = json.loads(req)
            headers = merge_header(req['headers'], auth_dict[auth_type])
            req['headers'] = headers
            https_flag = False
            if url.startswith('https'):
                https_flag = True
            body = req['body']
            try:
                body = json.loads(body)
            except Exception as e:
                pass
            if req['method'] in det_methods and sql_det_status:
                sql_det_req = {
                    'url': url,
                    'method': req['method'],
                    'headers': headers,
                    'body': body
                }
                sqlite_write_lock.acquire()
                if url not in scan_url:
                    scan_url.append(url)
                    api.sqli_detection(sql_det_req, https_flag)
                    printf(f'sqlmap target ==>> {url} is starting..')
                sqlite_write_lock.release()

            if req['method'] == 'POST':
                response = requests.post(url=url, headers=headers, json=body, proxies=proxy, verify=False)
            if req['method'] == 'GET':
                response = requests.get(url=url, headers=headers, proxies=proxy, verify=False)
            print(f'{req["method"]} url={url} status={response.status_code}')
        except Exception as e:
            print(e.args)
            continue

def multi_repeater(records: list, auth_dict: dict, sql_det_methods,sql_det_status):
    for record in records:
        repeater(record=record, auth_dict=auth_dict, det_methods=sql_det_methods,sql_det_status=sql_det_status)


if __name__ == '__main__':

    config = yaml.safe_load(open('./global_config.yaml', 'r', encoding='utf-8'))
    positions = config['target']['auth']['position']['headers']
    auth_dict = config['target']['auth']['value']
    schedule = config['target']['schedule']
    start_time = schedule['start_time']
    start_time_stamp = int(time.mktime(time.strptime(start_time, '%Y-%m-%d %H:%M:%S')))
    # 用户token
    user_token = schedule.get('auth_field', auth_dict['upper_permission'])
    threads_num = schedule['threads']
    sql_det_methods = schedule['sql_det_methods']
    proxy = schedule['proxy']
    sql_det_status = schedule['sql_det_status']
    while 1:
        now = int(time.time())
        if now < start_time_stamp:
            time_step = start_time_stamp - now
            if time_step < 15 * 60:
                print(f'-当前时间-{time.strftime("%Y-%m-%d %H:%M:%S")}-未达到触发任务时间--休眠{time_step}秒')
                time.sleep(time_step)
            else:
                print(f'-当前时间-{time.strftime("%Y-%m-%d %H:%M:%S")}-未达到触发任务时间--休眠{15 * 60}秒')
                time.sleep(15 * 60)
        else:
            break
    records = get_all_records()
    req_length = math.ceil(len(records) / threads_num)
    records_list = [records[(i) * req_length:(i + 1) * req_length] for i in range(0, threads_num)]
    threads_list = []
    for record in records_list:
        thread = threading.Thread(target=multi_repeater, args=(record, auth_dict, sql_det_methods,sql_det_status))
        threads_list.append(thread)
        thread.start()
    for i in threads_list:
        i.join()
