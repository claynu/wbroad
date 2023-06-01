#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""
import re
import string

from lib.core.enums import PRIORITY
from colorama import init
init(autoreset=False)


def printf(log, type=1):
    print(f'\033[3{type}m{log}\033[0m')


__priority__ = PRIORITY.LOWEST



def dependencies():
    pass


def tamper(payload, **kwargs):
    res = b''
    for w in payload:
        if w in string.digits:
            continue
        h = (hex(ord(w))[2:]).encode()
        u = b'\u'+b'0'*(4-len(h)) + h
        res += u
    printf(f'[+][payload]: {payload} -> {res.decode()}[+]', 2)
    return res.decode()
