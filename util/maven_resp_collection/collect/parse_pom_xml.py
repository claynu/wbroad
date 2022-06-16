# encoding:utf-8
import json
from xml.dom.minidom import parse

import cloudscraper

from collect import headers_format, parse_html


def parse_xml(xml_file):
    res_list = []
    domTree = parse(xml_file)
    rootNode = domTree.documentElement
    dependencies = rootNode.getElementsByTagName("dependencies")[0]
    for dependency in dependencies.getElementsByTagName('dependency'):
        groupId = dependency.getElementsByTagName("groupId")[0].childNodes[0].data
        artifactId = dependency.getElementsByTagName("artifactId")[0].childNodes[0].data
        version = dependency.getElementsByTagName("version")
        if version:
            version = version[0].childNodes[0].data
        else:
            version = ""
        res_list.append([groupId, artifactId, version])
    return res_list


def get_vul_info(groupId, artifactId, version):
    url = ""
    res_vul_list = {}
    if version:
        url = f"https://mvnrepository.com/artifact/{groupId}/{artifactId}/{version}"
    else:
        url = f"https://mvnrepository.com/artifact/{groupId}/{artifactId}"
    # print(url)
    scraper = cloudscraper.create_scraper()
    scraper.headers = headers_format.format()
    resp = scraper.get(url=url)
    text = resp.text
    if resp.text.find("Not Found:") != -1:
        print("请求地址存在异常")
        return
    if version:
        infos = parse_html.parse_info_html(text)
        if infos:
            return infos
        else:
            return "safe"
    else:
        # urls = parse_html.parse_vul_html(text)
        return "unKnow version, pls check by yourself url = {}".format(url)
    return res_vul_list


if __name__ == '__main__':
    xml_file = '../lib/pom.xml'
    # xml_webgoat_file = '../lib/pom_webgoat.xml'
    res_vul_list = {}
    for i in parse_xml(xml_file):
        res = get_vul_info(i[0], i[1], i[2])
        # print(f"{i[1]} {i[2]} {res}")
        print("%-40s%-10s%s" % (i[1], i[2], res))
        if res:
            res_vul_list[i[1]] = {i[2]: res}
    print("*" * 45)
    print(json.dumps(res_vul_list))
