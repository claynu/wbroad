import _thread
import re

import requests
import cloudscraper
from pymysql import IntegrityError

from collect import parse_html, headers_format
import pymysql

requests.urllib3.disable_warnings()


def connect_mysql():
    db = pymysql.connect(host="127.0.0.1", user="root", password="root", database="maven_vul_info", port=3306)
    return db

def get_url(status=0,num=1,table="group"):
    con = connect_mysql()
    cursor = con.cursor()
    sql = f"select id, url from `{table}` where status = {status} limit {num}"
    print(sql)
    cursor.execute(sql)
    return cursor.fetchall()

# ids = [1,2,3]
def update_status(ids,table="group"):
    if len(ids) == 1:
        sql = f"update `{table}` set status = 1 where id in ({ids[0]})"
    else:
        sql = f"update `{table}` set status = 1 where id in {str(tuple(ids))}"
    print(sql)
    execone_sql(sql)


def delete_record(ids, table="group"):
    if len(ids) == 1:
        sql = f"delete from `{table}` where id in ({ids[0]})"
    else:
        sql = f"delete from `{table}`  where id in {str(tuple(ids))}"
    print(sql)
    execone_sql(sql)

# list 格式 data
def execmany_sql(sql,data):
    try:
        data = set(data)
        con = connect_mysql()
        cursor = con.cursor()
        cursor.executemany(sql, tuple(data))
        con.commit()
        con.close()
    except IntegrityError as e:
        print(e.args)

def execone_sql(sql):
    try:
        con = connect_mysql()
        cursor = con.cursor()
        cursor.execute(sql)
        con.commit()
        con.close()
    except IntegrityError as e:
        print(e.args)

def update_mysql(vul_list):
    datas = []
    for vul in vul_list:
        vul_num = vul[1]
        vul_info = vul[0]
        version = vul_info.split('/')[-1]
        groupId = vul_info.split('/')[2]
        artifactId = vul_info.split('/')[3]
        datas.append((groupId, artifactId, version, vul_num))
    datas = tuple(datas)
    print(datas)
    try:
        con = connect_mysql()
        cursor = con.cursor()
        sql = "insert ignore  into vul_information(groupId, artifactId, version, vuln_info) value(%s,%s,%s,%s)"
        cursor.executemany(sql, datas)
        con.commit()
        con.close()
    except Exception as e:
        print(e.args)


def insert_group_url(url,group_id):
    sql = f'insert ignore into `group`(url,groupId) value("{url}","{group_id}")'
    print(sql)
    execone_sql(sql)

def insert_art_urls(urls):
    sql = "insert ignore into artifact(url) value(%s)"
    execmany_sql(sql, urls)

def query(num=10):
    urls = get_url(num=num, table="artifact")
    ids = []
    delete_ids = []
    append_urls = []
    print(urls)
    for url in urls:
        id = url[0]
        url = url[1]
        group_id = url.split("artifact/")[1]
        if group_id.find('/') == -1:
            # 将url 移至 group 删除改url
            delete_ids.append(id)
            insert_group_url(url,group_id)
            print("insert")
            continue
        scraper = cloudscraper.create_scraper()
        scraper.headers = headers_format.format()
        text = scraper.get(url=url).text
        vuln_html = parse_html.parse_vul_html(text)
        print(vuln_html)
        if vuln_html is not None:
            update_mysql(vuln_html)
        ids.append(id)
        print(f"{url} is done")
    if ids:
        update_status(ids, table="artifact")
    if delete_ids:
        delete_record(delete_ids, table="artifact")

# def collect_categories():
#     for page in range(1, 20):
#         url = f"https://mvnrepository.com/open-source?p={page}"
#         scraper = cloudscraper.create_scraper()
#         scraper.headers = headers_format.format()
#         text = scraper.get(url=url).text
#         sources = parse_html.parse_open_source_html(text)
#         if sources:
#             sql = "insert ignore  into categories(url) value(%s)"
#             execmany_sql(sql, sources)


# 根据groupId获取对于的组件url
def collect_url(num=10):
    urls = get_url(num=num,table="group")
    ids = []
    for url in urls:
        id = url[0]
        url = url[1]
        for page in range(1, 20):
            req_url = "{}?p={}".format(url,page)
            scraper = cloudscraper.create_scraper()
            scraper.headers = headers_format.format()
            resp = scraper.get(url=req_url)
            text = resp.text
            if resp.text.find("Not Found:")!= -1:
                break
            urls = parse_html.parse_url_html(text)
            if urls:
                insert_art_urls(urls)
        ids.append(id)
        print(f"{url} is done")
    update_status(ids,table="group")


# 从maven索引文件获取groupId
def get_group_by_index():
    f = open(r"../lib/text","r")
    t = []
    for i in f.readlines():
        i = i.replace("\n","")
        artifacts = i.split("|")
        con = connect_mysql()
        cursor = con.cursor()
        for a in artifacts:
            url = f"https://mvnrepository.com/artifact/{a}"
            sql = f'insert ignore into group(groupId,url) value("{a}","{url}");'
            print(sql)
            cursor.execute(sql)
            con.commit()

def thread_s():
    while 1:
        collect_url()
if __name__ == '__main__':
    # collect_url()
    _thread.start_new_thread(thread_s,())
    while 1:
        query()
    # _thread.start_new_thread()
    # collect_categories()



