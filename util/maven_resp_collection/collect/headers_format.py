# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2022/4/7 14:51
import json


def format():
    headers = open("headers.txt","r").read()
    result_dict = {}
    for line in headers.split("\n"):
        if line == "" or str.isspace(line):
            continue
        line = line.split(": ")
        result_dict[line[0].replace(' ', '')] = line[1]
        result = f"\"{line[0].replace(' ','')}\": \"{line[1]}\","
        # print(result)
    # print("\n\n")
    # print(result_dict)
    # return json.dumps(result_dict)
    return result_dict


if __name__ == '__main__':
    # pass
    print(format())