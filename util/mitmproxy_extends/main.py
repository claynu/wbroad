# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2022/8/19 16:17
# todo 集成其他几个工具
import datetime
import multiprocessing
import os
import re
import subprocess
from subprocess import call

import yaml
from colorama import init

import proxy_script.bin.sqli_api as sqlapi

init(autoreset=False)

menu = ''

funcs = ['mitmproxy集成工具 input q/Q/quit',
         '0.修改配置',
         '1.启动mitmproxy代理',
         '2.dirSearch目录探测',
         '3.替换token重放',
         '4.导出repeater结果',
         '5.查看repeater结果',
         '6.查看sqlmapapi详情',
         '7.定时重放(sql,xray)',
         '8.开启本地(sqlmapapi)',
         '9.打印菜单/刷新配置']

for fun in funcs:
    fun_format = '[+]{:10}-{:30}{:5}[+]\n'.format('-' * 10, fun.ljust(30)[:30].replace(' ', '-'), '-' * 5)
    menu += fun_format


def printf(log, type=2):
    ''':type  1 red  2green  3 yellow  '''
    print(f'\033[3{type}m{log}\033[0m')


def print_menu(menu):
    print("\033[2J")
    printf(menu, 2)


def run_command(command):
    # run(command,shell=True)
    call(command, creationflags=subprocess.CREATE_NEW_CONSOLE)


def start_process(command):
    p = multiprocessing.Process(target=run_command, args=(command,), group=None)
    p.daemon = True
    p.start()
    printf(f'子进程  {command}  启动中，请稍后...', type=2)
    p.join(1)


def start_proxy(config):
    ''''
    启动mitmproxy
    '''
    global path
    upstream_proxy = config['mitm']['upstream_proxy']
    listen_port = config['mitm']['port']
    listen_host = config['mitm']['host']
    encrypt_bin = config['mitm']['encrypt_bin']
    plugin = config['plugin']
    encrypt_proxy_port = config['mitm']['encrypt_proxy_port']
    request_decoder = config['request_decoder']
    if request_decoder:
        printf(f'加密加签代理启动中... listen 127.0.0.1:{encrypt_proxy_port}')
        start_process(
            f'cmd /k {encrypt_bin} -s {path}proxy_script{os.path.sep}encrypt_proxy.py -p {encrypt_proxy_port} --ssl-insecure --set tls_version_client_min=TLS1')
    if plugin['xray']['enable']:
        exec_path = plugin['xray']['exec_path']
        port = plugin['xray']['port']
        if not upstream_proxy:
            upstream_proxy = f' --mode upstream:http://127.0.0.1:{port} '
        command = f'{exec_path}  webscan  --listen 127.0.0.1:{port} --html-output {path}{"xray_log" + os.path.sep}{datetime.datetime.now().strftime("%Y%m%d-%H%M%S")}.html '
        start_process(command)
    else:
        if not upstream_proxy:
            upstream_proxy = ''
        else:
            upstream_proxy = f' --mode upstream:{upstream_proxy} '
    host_config = ''
    if listen_host != '' or listen_host != '127.0.0.1':
        host_config = f'--listen-host {listen_host}'
    command = f'cmd /k mitmdump {upstream_proxy} -s {path}proxy_script{os.path.sep}proxy.py -p {listen_port} {host_config} --ssl-insecure --set tls_version_client_min=TLS1 --set connection_strategy=lazy'
    start_process(command)
    printf(
        'client（web/burp/postman） ===> this mitmproxy(decrypt) ====> upstream proxy（xray/burp/server） ====> encrypt_proxy ====> target_host')


def start_dirsearch(config):
    dirsearch = config['plugin']['dirsearch']
    root_urls = dirsearch['root_url']
    headers = dirsearch.get('headers', None)
    proxy_cmd = ''
    proxy = dirsearch.get('proxy', None)
    headers_cmd = ''
    if proxy and proxy != '':
        proxy_cmd = f'--proxy={proxy}'
    if headers and headers != {}:
        for header in headers.keys():
            headers_cmd += f" -H {header}:{headers[header]}"
    wordlist = ''
    if dirsearch['dict']:
        wordlist = f'-w {dirsearch["dict"]}'
    if not root_urls:
        printf('请修改全局配置中 plugin ==> dirsearch ==> root_url', 1)
        return
    for root_url in root_urls:
        command = f'cmd /k python {dirsearch["exec_path"]} -u {root_url} {wordlist} {headers_cmd} {proxy_cmd} --full-url'
        start_process(command)


def sqldet_res(user):
    global project
    res = sqlapi.get_result(user=user, project=project)
    if res == {}:
        printf('当前无任务!', 2)
        return
    index = 0
    for i in res.keys():
        index += 1
        res[i]['taskid'] = i
        if res[i]['status'] == 'terminated':
            if res[i]['result'] is not None:
                if res[i]['result'] == 'Pass':
                    printf(f'第{index}个: {res[i]}', 2)
                elif res[i]['result'] == 'Exception':
                    # res[i]['log_url'] = sqli_config['url'] + f"/getLogs/{taskid}"
                    printf(f'第{index}个: 日志地址 {config["plugin"]["sqlmapapi"]["url"]}/getLogs/{i}   {res[i]}', 5)
                else:
                    details = sqlapi.get_scan_detail(taskid=res[i]['taskid'])
                    result_detail = details['detail']
                    printf(f'第{index}个:  {details}', 1)
                    printf(f'[+] 注入详情{">" * 35}')
                    if isinstance(result_detail,list):
                        for result in result_detail:
                            value = result.get('value',[{}])
                            value = value if isinstance(value,dict) else value[0]
                            if isinstance(value,str): continue
                            data = value.get('data',None)
                            if data is None:
                                continue
                            parameter = value['parameter']
                            dbms = value.get('dbms')
                            dbms = '' if dbms is None else dbms
                            dbms_version = value['dbms_version']
                            for vul_key in data.keys():
                                title = data[vul_key]['title']
                                payload = data[vul_key]['payload']
                                msg = f"----- \033[32m类型:  \033[31m{title.ljust(50)} \033[32m数据库 \033[31m{dbms.center(15)} \033[32m 参数 \033[31m{parameter.ljust(15)} \033[32mpayload = \033[31m{payload}"
                                msg = f'\033[32m{msg}\033[0m'
                                print(msg, end='\n')
                    else:
                        parameter = re.findall(r"'parameter': '(.*?)',", result_detail)
                        dbms = re.findall(r"'dbms': '(.*?)',", result_detail)
                        dbms = '' if dbms == [] else dbms[0]
                        parameter = '' if parameter == [] else parameter[0]
                        payloads = re.findall(r"'payload': '(.*?)',", result_detail)
                        titles = re.findall(r"'title': '(.*?)',", result_detail)
                        for i in range(0, len(payloads)):
                            payload = payloads[i]
                            if (i > len(titles) - 1):
                                title = titles[-1]
                            else:
                                title = titles[i]
                            msg = f"----- \033[32m类型: \033[31m{title} \033[32m数据库 \033[31m{dbms} \033[32m 参数 \033[31m{parameter} \033[32mpayload = \033[31m{payload}"
                            msg = f'\033[32m{msg}\033[0m'
                            print(msg, end='\n')
                    printf(f'[+]{"<"*35}END [+]')

            else:
                printf(f'第{index}个:  {res[i]}', 2)
            continue
        if res[i]['status'] == 'running':
            printf(f'第{index}个: {res[i]}', 4)
            continue
        printf(f'{res[i]}', 1)


def sqldet_log(taskid):
    """
    查询日志
    :param user:
    :return:
    """
    global project
    res = sqlapi.get_scan_detail(taskid=taskid)
    if res['0'] == '当前无任务':
        printf('当前无任务!', 2)
        return
    for i in res:
        if res[i]['status'] == 'terminated':
            if res[i]['result'] is not None:
                details = sqlapi.get_scan_detail(taskid=res[i]['taskid'])
                if details['result_detail'] == '未扫描到SQL注入点':
                    printf(f'第{i}个:  {details}', 2)
                else:
                    printf(f'第{i}个:  {details}', 1)
            else:
                printf(f'第{i}个:  {res[i]}', 2)
            continue
        if res[i]['status'] == 'running':
            printf(f'{res[i]}', 3)
            continue
        printf(f'{res[i]}', 1)


def start_local_sqlmapapi(command):
    start_process(command)


def not_local(c):
    printf(f'sqlmapapi url 不是 127.0.0.1 无法启动')


if __name__ == '__main__':

    path = os.path.abspath('.') + os.path.sep
    banner = '''
       ___     _       ___   __   __          _  _    _   
  / __|   | |     /   \  \ \ / /         | \| |  | | | | 
 | (__    | |__   | - |   \ V /    ___   | .` |  | |_| | 
  \___|   |____|  |_|_|   _|_|_   |___|  |_|\_|   \___/  
_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""| 
"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
'''
    printf(banner, type=2)
    printf('-' * 56)
    printf(menu, type=2)
    func_dict = {
        '0': os.system,
        '1': start_proxy,
        '2': start_dirsearch,
        '3': start_process,
        '4': start_process,
        '5': os.system,
        '6': sqldet_res,
        '7': start_process,
        '8': start_local_sqlmapapi,
        '9': print_menu,
    }
    while 1:
        index = input('请输入对应功能编号:')
        config = yaml.safe_load(open('global_config.yaml', 'r', encoding='utf-8'))
        project = config["plugin"]["sqlmapapi"]["project"]
        db_file = yaml.safe_load(open('global_config.yaml', 'r', encoding='utf-8'))['db_file']
        system_name = db_file.replace('/', '').replace('\\', '').replace('db', '').replace('.','')
        report_name = './report/' + f'{system_name}-report.html'
        protocol, prefix, local_sqlmap_port = config["plugin"]["sqlmapapi"]["url"].split(':')
        if prefix.find('127.0.0.1') == -1:
            func_dict['8'] = not_local
        command_dict = {
            '0': f'start {path}global_config.yaml',
            '1': config,
            '2': config,
            '3': f'python {path}proxy_script{os.path.sep}bin{os.path.sep}repeater.py',
            '4': f'python {path}proxy_script{os.path.sep}bin{os.path.sep}export.py',
            '5': f'start {report_name}',
            '6': config["plugin"]["sqlmapapi"]["user"],
            '7': f'python {path}proxy_script{os.path.sep}bin{os.path.sep}repeater_by_schedule.py',
            '8': f'cmd /k python {path}sqlmapdpi{os.path.sep}sqlmap-master{os.path.sep}sqlmapapi.py -s -p {local_sqlmap_port}',
            '9': menu
        }
        index = index.strip().lower()
        if index not in [str(i) for i in range(0, 10)]:
            if index == 'q' or index == 'quit':
                exit(-1)
            continue
        try:
            func_dict[index](command_dict[index])
        except Exception as e:
            printf(f'{e.args}')
