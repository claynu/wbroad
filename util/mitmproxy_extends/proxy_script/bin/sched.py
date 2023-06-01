# -*-coding:utf-8 -*-
# version: python3.8.6
# author: clay_nu
# datetime: 2022/9/30 15:48
# describe: 定时任务测试
import datetime

from apscheduler.schedulers.blocking import BlockingScheduler

scheduler = BlockingScheduler() # 后台运行

@scheduler.scheduled_job("cron",day='*',hour='*',minute='*',second='*/10')
def test_schedule():
    print(datetime.datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))


if __name__ == '__main__':
    scheduler.start()
