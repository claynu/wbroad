import requests
import cloudscraper
from collect import parse_html, headers_format
import pymysql

requests.urllib3.disable_warnings()


def connect_mysql():
    db = pymysql.connect(host="127.0.0.1", user="root", password="root", database="maven_vul_info", port=3306)
    return db

# list 格式 data
def execmany_sql(sql,data):
    try:
        con = connect_mysql()
        cursor = con.cursor()
        cursor.executemany(sql, tuple(data))
        con.commit()
        con.close()
    except Exception as e:
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
        sql = "insert into vul_information(groupId, artifactId, version, vuln_info) value(%s,%s,%s,%s)"
        cursor.executemany(sql, datas)
        con.commit()
        con.close()
    except Exception as e:
        print(e.args)


def insert_art_url(urls):
    sql = "insert into artifact(url) value(%s)"
    execmany_sql(sql, urls)
    # try:
    #     con = connect_mysql()
    #     cursor = con.cursor()
    #     sql = "insert into artifact(url) value(%s)"
    #     cursor.executemany(sql, tuple(urls))
    #     con.commit()
    #     con.close()
    # except Exception as e:
    #     print(e.args)


def query():
    url = "https://mvnrepository.com/artifact/com.alibaba/fastjson"
    scraper = cloudscraper.create_scraper()
    scraper.headers = headers_format.format()
    text = scraper.get(url=url).text
    vuln_html = parse_html.parse_vul_html(text)
    print(vuln_html)
    if vuln_html is None:
        return
    update_mysql(vuln_html)


def collect_categories():
    for page in range(1, 10):
        url = f"https://mvnrepository.com/open-source?p={page}"
        scraper = cloudscraper.create_scraper()
        scraper.headers = headers_format.format()
        text = scraper.get(url=url).text
        sources = parse_html.parse_open_source_html(text)
        for i in sources:
            print(i)


def collect_url():
    for source in open("maven_resource/open_sources_url.txt", "r").readlines():
        for page in range(1, 9999):
            url = "{}?p={}".format(source.replace("\n", ""), page)
            scraper = cloudscraper.create_scraper()
            scraper.headers = headers_format.format()
            resp = scraper.get(url=url)
            text = resp.text
            if resp.text.find("Not Found:")!= -1:
                break
            urls = parse_html.parse_url_html(text)
            if urls:
                insert_art_url(urls)
        print(f"{source} is done")



if __name__ == '__main__':
    collect_url()
    # query()
    # collect_categories()
