# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2023/5/27 10:12

import logging
import colorlog


def get_logger(level=logging.INFO):
    # 创建logger对象
    logger = logging.getLogger()
    # 设置默认输出等级
    logger.setLevel(level)
    # 创建控制台日志处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    datefmt = '%Y-%m-%d %H:%M:%S'
    # 定义颜色输出格式
    color_formatter = colorlog.ColoredFormatter(
        '{log_color}{asctime} {levelname}:  {filename} {message}',
        datefmt=datefmt,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_black',
        },
        style='{'
    )
    # 将颜色输出格式添加到控制台日志处理器
    console_handler.setFormatter(color_formatter)
    # 移除默认的handler
    for handler in logger.handlers:
        logger.removeHandler(handler)
    # 将控制台日志处理器添加到logger对象
    logger.addHandler(console_handler)
    return logger


if __name__ == '__main__':
    logger = get_logger(logging.DEBUG)
    logger.debug('debug message')
    logger.info('info message')
    logger.warning('warning message')
    logger.error('error message')
    logger.critical('critical message')