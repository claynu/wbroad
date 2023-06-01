# -*- coding:utf-8 -*-
import json
import os
import time

import yaml
import sqlite3
from colorama import init
init(autoreset=False)

db_file = yaml.safe_load(open('./global_config.yaml', 'r', encoding='utf-8'))['db_file']
# db_file = '../db/rcmmngwebsh.db'

def con_sqlite():
    global db_file
    con = sqlite3.connect(db_file)
    return con

role_dict={
    "upper_permission": "高",
    "lower_permission1": "低1",
    "lower_permission2": "低2",
    "without_permission": "无",
}

def get_all_records():
    con = con_sqlite()
    cursor = con.cursor()
    sql = 'select response.url,resp,token,resp_headers,response.req,length,resp_status,check_type,risk_type,role_type from response left join request on response.req_id=request.id order by  req_id,token'
    cursor.execute(sql)
    res = cursor.fetchall()
    return res



def printf(log,type=1):
    print(f'\033[3{type}m{log}\033[0m')

def format_http(headers,resp):
    # json => http
    headers = json.loads(headers)
    value = ''''''
    for key in headers.keys():
        value+=(f'{key}:{headers[key]}\r\n')

    if resp :
        value += f'\r\n{resp}'
    else:
        value += '\r\n\r\n'
    return value

def export(vuls,filename='report.html'):

    f = open(filename,'w',encoding='utf-8')
    htmls.append(f"<script class='web-vulns'>webVulns.push({vuls})</script>")
    f.writelines(htmls)
    f.close


def format_req(req):
    # req json str
    req = json.loads(req)
    raw_str = f"{req['method']} {req['url']} HTTP/1.1\r\n"
    for header in req['headers'].keys():
        raw_str += f'{header}: {req["headers"][header]}\r\n'
    if req['body']:
        raw_str += f'\r\n{req["body"]}'
    else:
        raw_str += '\r\n\r\n'
    return raw_str

if __name__ == '__main__':
    res = get_all_records()
    check_lists = ''
    for url,resp,token,resp_headers,req,length,resp_status,check_type,risk_type,role_type in res:
        # if int(length)>1000:
        #     resp = 'response is too large'
        resp =  resp.replace('<','&lt;')
        req =  req.replace('<','&lt;')
        resp =  resp.replace('<','&gt;')
        req =  req.replace('<','&gt;')
        max = len(resp)
        if max > 50:
            max = 50
        resp_short = resp[0:max]
        try:
            resp_short = json.loads(res)
        except Exception:
            pass
        record = {"create_time":int(time.time()*1000),"detail":{"addr":url,"token":token,"snapshot":[[format_req(req),format_http(resp_headers,resp)]],"extra":{"param":{}}},"plugin":check_type,"target":{"url":url},"length":length,"status":resp_status, "risk":risk_type,"role":role_dict[role_type],"resp_short":resp_short}
        check_lists += json.dumps(record)+','
    system_name = db_file.replace('/','').replace('\\','').replace('db','').replace('.','')
    filename = './report/'+f'{system_name}-report.html'
    export(check_lists[0:-1],filename=filename)
    os.system(f'start {filename}')


