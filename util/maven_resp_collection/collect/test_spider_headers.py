import json
from xml.dom.minidom import parse

import cloudscraper
import cfscrape
import time
from selenium.webdriver.chrome.options import Options
from selenium import webdriver
# https://chromedriver.storage.googleapis.com/index.html 下载对应版本驱动
# https://github.com/mozilla/geckodriver/releases
width = 400
height = 768
chrome_options = Options()
chrome_options.page_load_strategy = 'normal'
chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
# chrome_options.add_experimental_option('useAutomationExtension', True)
# chrome_options.add_argument('--no-sandbox')
# chrome_options.add_argument('--lang=en')
# chrome_options.add_argument('--ignore-certificate-errors')
# chrome_options.add_argument('--allow-running-insecure-content')
# chrome_options.add_argument('--disable-notifications')
# chrome_options.add_argument('--disable-dev-shm-usage')
# chrome_options.add_argument('--disable-browser-side-navigation')
# chrome_options.add_argument('--mute-audio')
# chrome_options.headless = True
# chrome_options.add_argument('--force-device-scale-factor=1')
# chrome_options.add_argument(f'window-size={width}x{height}')

if __name__ == '__main__':
    # proxy = {"https":"127.0.0.1:8080"}
    url = 'https://173.82.135.41/artifact/'
    # 如果chrome不是安装在默认路径，则要driver = webdriver(executable_path='chrome.exe的指定路径')
    from selenium import webdriver
    driver = webdriver.Chrome(executable_path='driver/chromedriver.exe', options=chrome_options)
    driver.set_page_load_timeout(7)
    driver.get(url)
    cookies = driver.get_cookies()
    Cookie = ''
    for i in cookies:
        print(f"{i['name']}={i['value']}")
        Cookie += f"{i['name']}={i['value']}"
    scraper = cloudscraper.create_scraper()
    scraper.headers = {
        'Cookie':Cookie
    }
    res = scraper.get(url)
    print(res.status_code)
