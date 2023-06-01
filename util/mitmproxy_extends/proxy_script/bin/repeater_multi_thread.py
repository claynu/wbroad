# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2022/11/16 18:45
import json
import sqlite3
import threading

import requests
import yaml
from colorama import init

import customer as custom

init(autoreset=False)
# sqlite 仅支持1写

sqlite_write_lock = threading.Lock()
# db_file = '../db/rcmmngwebsh.db'
decrypt_flag = 0
risk_type_dict = {
    "vertical": "垂直越权风险",
    "horizon": "水平越权风险",
    "unauthorized": "未授权风险",
    "none": "无",
    "unknown": "未知"
}


def con_sqlite():
    global db_file
    return sqlite3.connect(db_file)


def init_db():
    con = con_sqlite()
    sql = '''CREATE TABLE if not exists `response` (
	`id`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`req_id`	TEXT NOT NULL,
	`url`	TEXT NOT NULL,	
	`length`	TEXT NOT NULL,	
	`token`	TEXT NOT NULL,
	`resp`	TEXT NOT NULL,
	`resp_headers`	TEXT NOT NULL,
	`check_type`	TEXT NOT NULL,
	`resp_status`	TEXT NOT NULL,
	`role_type`	TEXT NOT NULL,
	`risk_type`	TEXT NOT NULL,
	`remark`	TEXT,
	 UNIQUE("req_id","token")
);'''
    con.execute("pragma encoding='UTF-8'")
    con.execute(sql)
    con.commit()
    con.close()


def get_all_records():
    con = con_sqlite()
    cursor = con.cursor()
    sql = 'select id,url, req from request'
    cursor.execute(sql)
    res = cursor.fetchall()
    return res


def printf(log, type=1):
    print(f'\033[3{type}m{log}\033[0m')


def restore_res(tmp_list):
    global sqlite_write_lock
    sqlite_write_lock.acquire()
    req_id, url, token, length, resp, resp_headers, resp_status, check_type, role_type, risk_type = tmp_list
    # todo 部分请求入库失败
    con = con_sqlite()
    cursor = con.cursor()
    try:
        sql = f"insert into response(req_id,url,token,length,resp,resp_headers,resp_status,check_type,role_type, risk_type) values('{req_id}','{url}','{json.dumps(token)}','{length}','{resp}','{resp_headers}','{resp_status}','{check_type}','{role_type}','{risk_type}')"
        cursor.execute(sql)
    except Exception as e:
        if e.args[0].find('UNIQUE') != -1:
            printf(f'本记录已存在 {e.args}')
        else:
            printf(f'restore_res insert error {e.args} \nsql=  {sql}')
    con.commit()
    sqlite_write_lock.release()
    con.close()


def merge_header(origin, modify):
    for key in modify.keys():
        origin[key] = modify[key]
    return origin



def repeater(record: tuple, auth_dict: dict):
    """
    重放请求
    :param record:  sqlite 中取出的请求 (id, req)
    :param auth_dict:  认证信息  {'upper_permission': {'token': 'eyJ0eXAiOiJKV1QiLC'}}
    :return: none
    """
    res_dict = {}
    restore_res_param_temp_list = []
    for auth_type in auth_dict:
        id, url, req = record
        req = json.loads(req)
        headers = merge_header(req['headers'], auth_dict[auth_type])
        method = req['method']
        # url = req['url']
        body = req['body']
        try:
            if method == 'POST':
                response = requests.post(url=url, headers=headers, json=json.loads(body))
            if method == 'GET':
                response = requests.get(url=url, headers=headers)
            print(f'{method} url={url} status={response.status_code}')
            if "Content-Length" in response.headers:
                length = str(response.headers["Content-Length"])
            else:
                length = len(response.text)
            resp = response.text
            if decrypt_flag > 0:
                resp = custom.decrypt(response.text)
            res_dict[auth_type] = {
                'status_code': response.status_code,
                'length': length,
                'resp': resp,
            }
            restore_res_param_temp_list.append([id, url, auth_dict[auth_type], length, resp,
                        json.dumps(dict(response.headers)), response.status_code,
                        'check_permission', auth_type, ''])
        except Exception as e:
            print(e.args)
            continue
    # 处理响应
    vuln_type = check_auth_vuln(res_dict)
    print(res_dict)
    print(vuln_type)
    for params in restore_res_param_temp_list:
        params[-1] = vuln_type
        restore_res(params)

def check_auth_vuln(response: dict):
    """ 校验响应
    :param response:  默认为4 且顺序为 高到低
    :param keys:  权限
    :return:  risk_type
    """
    global risk_type_dict
    upper_permission_res = response.get('upper_permission',{})
    lower_permission1 = response.get('lower_permission1',{})
    lower_permission2 = response.get('lower_permission2',{})
    without_permission = response.get('without_permission',{})
    if upper_permission_res == lower_permission1 == lower_permission2 == without_permission:
        return risk_type_dict['unauthorized']
    if upper_permission_res != lower_permission1 == lower_permission2 != without_permission:
        return risk_type_dict['horizon']
    if upper_permission_res != lower_permission1 != lower_permission2 != without_permission:
        return risk_type_dict['none']
    if upper_permission_res == lower_permission1 == lower_permission2 != without_permission:
        return risk_type_dict['vertical']
    return risk_type_dict['unknown']


# TODO LIST :
# 1. 结果校验 1. 未授权 2. 垂直 3. 水平  # 无
# 2. 多线程  需解决并发锁问题   sqlite 仅支持1写多读
# 3. 封装一个  res-> tofile 的类
'''
role_type : 角色类型
risk_type : 越权类型  vertical 垂直   horizon 水平    unauthorized  未授权  none 无  
'''

def multi_repeater(records:list,auth_dict:dict):
    for record in records:
        print(record)
        repeater(record=record, auth_dict=auth_dict)

if __name__ == '__main__':
    config = yaml.safe_load(open('../global_config.yaml', 'r', encoding='utf-8'))
    positions = config['target']['auth']['position']['headers']
    db_file = config['db_file']
    init_db()
    auth_dict = config['target']['auth']['value']
    print(auth_dict)
    threads_num = config['target']['auth']['threads']
    records = get_all_records()
    req_length = int(len(records)/threads_num)
    records_list = [records[(i) * req_length:(i + 1) * req_length] for i in range(0, threads_num)]
    threads_list = []
    for record in records_list:
        thread = threading.Thread(target=multi_repeater,args=(record,auth_dict))
        threads_list.append(thread)
        thread.start()
    for i in threads_list:
        i.join()
