import requests
import cloudscraper
from collect import parse_html, headers_format
import pymysql


requests.urllib3.disable_warnings()

def connect_mysql():
    db = pymysql.connect(host="127.0.0.1", user="root", password="root", database="maven_vul_info", port=3306)
    return db

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
        sql = "insert into vul_information(groupId, artifactId, version, vuln_info) value(%s,%s,%s,%s)"
        print("exec sql")
        cursor.executemany(sql, datas)
        con.commit()
        print("done")
        con.close()
    except Exception as e:
        print(e.args)


def query():
    url = "https://mvnrepository.com/artifact/com.alibaba/fastjson"
    scraper = cloudscraper.create_scraper()
    scraper.headers = headers_format.format()
    text = scraper.get(url=url, ).text
    vuln_html = parse_html.parse_vul_html(text)
    print(vuln_html)
    if vuln_html is None:
        return
    update_mysql(vuln_html)




if __name__ == '__main__':
    query()
