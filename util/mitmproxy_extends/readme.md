### 测试中心/安全测试小组/工具文档规范
### mitm 代理工具
> [mitm 基础](mitm.md)

[toc]

#### 1. 功能点介绍
![](./img/main.png)
0. 修改配置 --> 对应文件global_config.yaml
1. 启动mitmproxy 代理
    1. 流量流程图可参考 [https://processon.paas.cmbchina.com/home/view/link/6389ac04f75194488f27915a#mitmproxy](https://processon.paas.cmbchina.com/home/view/link/6389ac04f75194488f27915a#mitmproxy)
    2. 如果存在加密加签 需要 proxy_script目录下的 decrypt_proxy(解密) 和 encrypt_proxy(加密) 以及全局配置中的
      ```yaml
      request_decoder: true                       # 请求需解密/加密加签 需要完成bin/proxy_script目录下的 decrypt_proxy.py 和 encrypt_proxy.py
      mitm:
        port: 8081                                  # 监听端口
        host: 127.0.0.1                             # 默认127.0.0.1   # 99.15.156.161
        encrypt_proxy_port: 8089                    # 加密加签代理监听端口 前置条件 request_decoder = true
        upstream_proxy: http://127.0.0.1:8080       # proxy/解密代理的 上游代理
     ```
2. dirsearch目录探测
    1. 在全局配置中的plugin-dirsearch 中配置，会基于配置分别扫描root_url
   ```yaml 
   plugin: # 第三方拓展
     dirsearch: 
       exec_path: D:\TOOLS\dirsearch-master\dirsearch.py             # 脚本绝对路径
       headers:                                                      # dirsearch headers 配置
   #      cookie: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2Njg0MzUxODYsInVzZXJuYW1lIjoiend4In0.8JKhSLpL2Y2wvGad3z2B9-tBJ-yGa4T9_eFeecMa7cE'
   #    proxy: http://127.0.0.1:8080
       dict:  #D:\TOOLS\dirsearch-master\db\dicc.txt                 # 字典路径 空则使用dirsearch 默认字段
       root_url:  # 批量扫描
            - https://pbank-app-euaf.csuat.cmburl.cn/biz/  # 扫描的根url
            - https://pbank-app-euaf.csuat.cmburl.cn/cmf-app/ # 扫描的根url
   ```
3. 替换token重放
   1. 在代理保存的请求中替换对应的身份认证信息进行重放
   2. 配置如下
   ```yaml
   target:
     host:                                                     # 网站域名 支持正则匹配/列表 匹配上的请求才会处理后续流程包括sql 扫描 保存请求等
     - pbank-app-euaf.csuat.cmburl.cn
     blacklist:                                                # 黑名单配置 配置中的请求不会保存到db中
       suffix: js,gif,jpg,png,css,svg,json,encrypt_upload,ttf,ico   # 黑名单请求后缀  
       url:                                                    # 黑名单url
         - https://lf12-32-gateway-st.paasst.cmbchina.cn/front-rest-log/v2/encrypt_upload
         - https://lf12-32-gateway-st.paasst.cmbchina.cn/front-rest-log/v3/trace
     # 使用替换权限信息重返时需要
     auth:                                                     # 认证信息  需提供一个高权限，2个低权限
       threads: 5                                              # 重放线程数
       proxy:                                                  # 重放时是否使用代理
           enable: true
           http: 127.0.0.1:8089
           https: 127.0.0.1:8089
       position:                                               # 认证信息位置
         headers:                                              # 当前只支持 headers 中的鉴权方式 有几个配置几个
           - X-Auth-Token                                      # 字段名 可配置多个对应的value参数名需同步
           - Token                                             # 字段名 可配置多个对应的value参数名需同步
       value:                                                  # 对应字段的值
         upper_permission:   # 高权限用户
           X-Auth-Token: 35903511-c455-491a-b977-114693b9a4d2
           Token: eyJzaWduIjoiYWEwM2Y2YTgwMGJjNDRlM2U3ZTM0Mzg5NjljN2JhNjEiLCJ0b2tlbkluZm8iOnsiY3J0dGltIjoxNjY5OTcwNTYzMTAzLCJleHB0aW0iOjE2Njk5NzExNjMxMDMsInNlc3Npb25JZCI6IjM1OTAzNTExLWM0NTUtNDkxYS1iOTc3LTExNDY5M2I5YTRkMiIsInVzZXJpZCI6IjEwMDAwMDY1MDAifX0=
         lower_permission1:  # 低权限用户1
           X-Auth-Token: 35903511-c455-491a-b977-114693b9a4d2
           Token: eyJzaWduIjoiYWEwM2Y2YTgwMGJjNDRlM2U3ZTM0Mzg5NjljN2JhNjEiLCJ0b2tlbkluZm8iOnsiY3J0dGltIjoxNjY5OTcwNTYzMTAzLCJleHB0aW0iOjE2Njk5NzExNjMxMDMsInNlc3Npb25JZCI6IjM1OTAzNTExLWM0NTUtNDkxYS1iOTc3LTExNDY5M2I5YTRkMiIsInVzZXJpZCI6IjEwMDAwMDY1MDAifX0=
         lower_permission2:  # 低权限用户2 权限等级 同1
           X-Auth-Token: 35903511-c455-491a-b977-114693b9a4d2
           Token: eyJzaWduIjoiYWEwM2Y2YTgwMGJjNDRlM2U3ZTM0Mzg5NjljN2JhNjEiLCJ0b2tlbkluZm8iOnsiY3J0dGltIjoxNjY5OTcwNTYzMTAzLCJleHB0aW0iOjE2Njk5NzExNjMxMDMsInNlc3Npb25JZCI6IjM1OTAzNTExLWM0NTUtNDkxYS1iOTc3LTExNDY5M2I5YTRkMiIsInVzZXJpZCI6IjEwMDAwMDY1MDAifX0=
         without_permission: # 默认检查未授权访问 无权限
            X-Auth-Token: ''
            Token: ''

   
   ```
4. 导出重放的报告- 基于重放的响应以及角色的权限判断是否存在越权 
   1. 流程图参考 [https://processon.paas.cmbchina.com/home/view/link/63905aa2f9b63648281cf651#mitmproxy_权限校验流程](https://processon.paas.cmbchina.com/home/view/link/63905aa2f9b63648281cf651#mitmproxy_权限校验流程)
   2. ![](img/repeater.png)
5. 浏览器打开本项目扫描结果
6. 查看sqlmap扫描结果
   1. 前置：在使用 功能1的代理时在url中拼接上 配置中的flag 代理会将该请求自动发送至sqlmapapi进行sql扫描
   2. 查看对应扫描结果就可使用6功能， 基于不同的扫描结果(是否存在sql注入)输出的颜色不同
   ```yaml
   plugin:
      sqlmapapi: # sqlmapapi 调用
      #    url: http://55.13.157.115:6000  # 必须是  协议 + host + port
          url: http://127.0.0.1:9527
          user: heyu
          project:  lon_pbank                               # 项目名称 sqlmapapi 中基于该值区分项目归属
          flag: --sqldet--                                  # 标识url需要扫描sqli
          options:                                          # sqlmapapi 提交的扫描选项，根据key value 构建json
            level: 3
            risk: 3
            threads: 5
      #     proxy: http://55.13.157.115:8999                # 扫描代理
   ```
7. 定时重放
   1. 类似功能3 基于代理存储的请求 定时进行重放，主要用于工具扫描，联合xray 和 sqlmapapi
   2. 配置
   ```yaml
     schedule: # 定时重放请求
       start_time: "2022-11-18 23:40:00"  # 固定格式 开始时间
       threads: 2
       sql_det_status: enable
       sql_det_methods:       # 扫描以下配置的http method 请求
         - GET
         - POST
       proxy:
         http: 127.0.0.1:7777
         https: 127.0.0.1:7777
       auth_field: upper_permission # 高权限 对应选项为  upper_permission  lower_permission1  lower_permission2  without_permission
   ```
8. 开启本地sqlmapapi_web 
   1. 当存在加密加签又不想在服务器上开加解密代理时使用 
   2. 在原生sqlmapapi 基础上修改，由于要兼容冉攀的版本 目前响应数据并不完整 但是不影响本地扫描
   

#### 2. 工具使用
1. 启动入口 main.py 通过```python main.py``` 或者双击start.bat 
2. 第一步修改配置，通过功能0 或者直接修改根目录的 global_config.yaml
   1. > 注： 如果存在加解密 需先完成 proxy_script目录下的 decrypt_proxy.py 和 encrypt_proxy.py 然后request_decoder 需标注为true
      > >  1. 常见加解密方式在proxy_script/bin/util.py 中 `from bin import util` 引入即可
      > >  2. 加解密情况下 工具会启动两个代理 第一个代理以配置中mitm模块的host、port、upstream_proxy启动 流量会先经过decrypt_proxy.py -》 proxy.py
      > >  3. 加密加签代理会单独启动一个端口监听，配置为 encrypt_proxy_port
   2. 完成如下配置 
      ```yaml
      db_file: db/lon_pbank.db                      # 自定义 数据库文件名 每个项目单独命名 固定格式 db/xxx.db
      request_decoder: true                         # 请求需解密/加密加签 需要完成proxy_script目录下的 decrypt_proxy.py 和 encrypt_proxy.py
      
      mitm:
        port: 8081                                  # 监听端口
        host: 127.0.0.1                             # 默认127.0.0.1   # 99.15.156.161
        encrypt_proxy_port: 8089                    # 加密加签代理 前置条件 request_decoder = true
        upstream_proxy: http://127.0.0.1:8080       # 上游代理
      
      
      target:
        host:                                                     # 网站域名 支持正则匹配/列表
        - pbank-app-euaf.csuat.cmburl.cn
        blacklist:                                                # 黑名单配置
          suffix: js,gif,jpg,png,css,svg,json,encrypt_upload,ttf,ico   # 黑名单请求后缀
          url:                                                    # 黑名单url
            - https://lf12-32-gateway-st.paasst.cmbchina.cn/front-rest-log/v2/encrypt_upload
            - https://lf12-32-gateway-st.paasst.cmbchina.cn/front-rest-log/v3/trace
      plugin:
         sqlmapapi: # sqlmapapi 调用
      #    url: http://55.13.157.115:6000  # 必须是  协议 + host + port
          url: http://127.0.0.1:9527
          user: heyu
          project:  lon_pbank                               # 项目名称 sqlmapapi 中的分类关键词默认域名
          flag: --sqldet--                                           # 标识url需要扫描sqli
          options:                                                    # sqlmapapi 提交的扫描选项，根据key value 构建json
            level: 3
            risk: 3
            threads: 5
      #      proxy: http://55.13.157.115:8999
      ```
3. 代理开启后，可burp抓包然后配置上游代理转发到本工具监听的端口
   1. 如果要进行sql扫描 只需要将请求放到burp的repeater模块，在path任意位置拼接上sqlmapapi配置中的flag即可(本例是--sqldet--)
      ```http
         POST /ibank-pbanking-asoc/userMan--sqldet--age/getUserInfo4Register HTTP/2
         Host: pbank-app-euaf.paasst.cmbchina.cn
         Cookie: FZ_STROAGE.cmbchina.cn=%
         User-Agent: 111
         Content-Length: 164
         
        
         {"payload":"vkRl0SUDj7MPHKHAd+wVNADYVLWIDayljw0QFVm+i9HQiaC8m4eQUZ7E3BpvHt8Mu5FnV2VAlTBcr0y3fTTPdShZjSZFQ0Q=","iv":"ZZ/+jk8qyHLzasoO","aad":"2022-12-08 17:08:16"}
      ```
   2. 如果是进行xray扫描 需将代理的 upstream_proxy 配置为xray 监听的端口 若存在加密加签 **需将xray的上游代理配置为加密加签监听的地址**

4. 其他功能点参考功能点介绍中的配置后直接使用即可



#### 3. 相关模板功能说明
1. 代理

#### 3. 工具相关三方库及使用方法 
1. mutilProcess 多进程三方库 
2. requests  实现http请求的库

####4. TODO_LIST
* [x] 上游代理https问题处理               优先级 **H**
* [x] 重构proxy脚本的代码逻辑，对复杂代码进行拆分   优先级 **H**
* [x] 控制台menu的输出 自动刷新                  优先级 **M**
* [x] ~~基于配置完成加密加签的功能  # 复杂度较高      优先级 **L**~~
* [x] 加密加签优先级问题          #              优先级 **L**
* [ ] ~~数据库存储数据的索引可配置    #             优先级 **L**~~
* [x] 重构repeater脚本的代码逻辑，对复杂代码进行拆分   优先级 **H**
* [ ] GUI 版本

#### 5. 靶场使用演示
> 环境为 pikachu靶场， 地址 localhost:80 
1. 代理基础配置
```yaml
db_file: db/pikachu                         # 修改数据库文件 (不存在的文件 工具会自动初始化)  
target:
  host:                                     # 网站域名 支持正则匹配/列表
  - localhost
  - pikachu.com                             # phpstudy 设置的第二域名为 pikachu.com

mitm:
  port: 8000                                  # 代理监听端口
# plugin 模块 按需配置  
plugin:
  sqlmapapi:                       
    #url: http://55.13.157.115:6001         # 必须是  协议 + host + port
    url: http://127.0.0.1:9527              # 如果要开启本地sqlmapapi 需使用 127.0.0.1 / localhost  
    user: heyu
    project: pikachu                        # 项目名称 sqlmapapi 中的分类关键词默认域名
    flag: --sqldet--                        # 标识url需要扫描sqli
    options:                                # sqlmapapi 提交的扫描选项，根据key value 构建json 如果不清楚可查看第6点
      level: 3
      risk: 3
      threads: 5
      #proxy: http://127.0.0.1:8089

```
2. 启动代理(入口为根目录的main.py / 双击start.bat)
   1. ![](./img/start_proxy.png)  
   2. 监听端口为 global_config.yaml中 mitm->port 本例配置为8000
   3. 然后将浏览器代理配置为burp， burp上游代理配置到8000
   4. ![img.png](./img/burp_upstream.png)
   5. 如果要对某一请求进行sql扫描 执行如下操作
      1. 如果是本地扫描 需要使用第8个功能项 开启本地sqlmapapi server
         ![开启本地sqlmapapi](./img/local_sqlmapapi.png)
      2. 将请求发送到repeater 
      3. 在path中添加 配置中(plugin->sqlmapapi->flag中配置的值) 本例为 `--sqldet--` 
      4. ![请求sql扫描](./img/repeater_sqldet.png)
   6. 如果要查看sql 扫描结果 
      1. 使用第6个功能项 (为方便演示 我这添加几个其他扫描结果的记录)
      2. ![sqlmap扫描结果](./img/sqli_result.png)
   7. 定时重放功能 / 批量扫描 (sql/xray)
      1. 先在启用代理情况下访问全系统页面/接口 或者使用rad + mitmproxy 代理 
      2. 常用命令 `rad -t "http://pikachu.com/" --http-proxy 127.0.0.1:8080 -full-text-output ./log/rad_log/pikachu.txt`  如果需要登录 可以使用 `-wait-login`
      3. ![rad爬虫](./img/rad.png)
      4. 采集完成后 配置如下模块
         1. `auth_field` 为 `auth` 模块对应的权限名 
         2.    
         ```yaml
           schedule: # 定时重放请求
             start_time: "2022-12-09 08:55:00"  # 固定格式 重放时间
             threads: 2
             sql_det_status: false   # true  是否进行sqlmap 扫描
             sql_det_methods:       # sql扫描以下配置的http method 请求
               - GET 
               - POST
             proxy:
               http: 127.0.0.1:7777   # 配置为xray 的代理地址
               https: 127.0.0.1:7777  
             auth_field: upper_permission # 高权限 对应选项为  upper_permission  lower_permission1  lower_permission2  without_permission
         ```
         3. 选择功能项 7  如果当前时间大于配置的开始时间会立即执行  否则定时执行 即可
      5. 





#### 5. 目录文件说明
```shell
├─img                   # 存放readme图片文件 
│  └─ XXX.PNG
├─sqldet_file           # sqlmapapi 扫描的文件
│  └─ xxx.txt
├─sqlmapdpi             # sqlmapapi web 封装的api
│  └─ xxx.api_utils.py
├─xray_log              # xray 日志目录
├─config.yaml           # xray 配置文件
├─export.py             # 重放的请求 导出脚本
├─global_config.yaml    # 全局配置文件
├─main.py               # 脚本入口 主函数
├─proxy.py              # mitm 拓展脚本
├─readme.md             # 工具说明
├─repeater.py           # 请求替换token重放脚本
├─xxx.db                # 数据库文件
├─xxx.db-report.html    # 导出的请求数据
├─start.bat             
├─start.bat - 快捷方式.lnk
```


#### sqlmapapi 支持的配置
```json

{
  "describe": "sqlmapapi 支持的配置",
  "success": true,
  "options": {
    "direct": null,
    "url": null,
    "logFile": null,
    "bulkFile": null,
    "requestFile": "/opt/tools/sqlmapaide_web/request_files/lzp/10-26-11-01-53/0.txt",
    "sessionFile": null,
    "googleDork": null,
    "configFile": null,
    "method": null,
    "data": null,
    "paramDel": null,
    "cookie": null,
    "cookieDel": null,
    "liveCookies": null,
    "loadCookies": null,
    "dropSetCookie": false,
    "agent": null,
    "mobile": false,
    "randomAgent": false,
    "host": null,
    "referer": null,
    "headers": null,
    "authType": null,
    "authCred": null,
    "authFile": null,
    "ignoreCode": null,
    "ignoreProxy": false,
    "ignoreRedirects": false,
    "ignoreTimeouts": false,
    "proxy": null,
    "proxyCred": null,
    "proxyFile": null,
    "proxyFreq": null,
    "tor": false,
    "torPort": null,
    "torType": "SOCKS5",
    "checkTor": false,
    "delay": 0,
    "timeout": 30,
    "retries": 3,
    "retryOn": null,
    "rParam": null,
    "safeUrl": null,
    "safePost": null,
    "safeReqFile": null,
    "safeFreq": null,
    "skipUrlEncode": false,
    "csrfToken": null,
    "csrfUrl": null,
    "csrfMethod": null,
    "csrfRetries": 0,
    "forceSSL": false,
    "chunked": false,
    "hpp": false,
    "evalCode": null,
    "optimize": false,
    "predictOutput": false,
    "keepAlive": false,
    "nullConnection": false,
    "threads": 5,
    "testParameter": null,
    "skip": null,
    "skipStatic": false,
    "paramExclude": null,
    "paramFilter": null,
    "dbms": null,
    "dbmsCred": null,
    "os": null,
    "invalidBignum": false,
    "invalidLogical": false,
    "invalidString": false,
    "noCast": false,
    "noEscape": false,
    "prefix": null,
    "suffix": null,
    "tamper": null,
    "level": 3,
    "risk": 3,
    "string": null,
    "notString": null,
    "regexp": null,
    "code": null,
    "smart": false,
    "textOnly": false,
    "titles": false,
    "technique": "BEUSTQ",
    "timeSec": 5,
    "uCols": null,
    "uChar": null,
    "uFrom": null,
    "dnsDomain": null,
    "secondUrl": null,
    "secondReq": null,
    "extensiveFp": false,
    "getAll": false,
    "getBanner": false,
    "getCurrentUser": false,
    "getCurrentDb": false,
    "getHostname": false,
    "isDba": false,
    "getUsers": false,
    "getPasswordHashes": false,
    "getPrivileges": false,
    "getRoles": false,
    "getDbs": false,
    "getTables": false,
    "getColumns": false,
    "getSchema": false,
    "getCount": false,
    "dumpTable": false,
    "dumpAll": false,
    "search": false,
    "getComments": false,
    "getStatements": false,
    "db": null,
    "tbl": null,
    "col": null,
    "exclude": null,
    "pivotColumn": null,
    "dumpWhere": null,
    "user": null,
    "excludeSysDbs": false,
    "limitStart": null,
    "limitStop": null,
    "firstChar": null,
    "lastChar": null,
    "sqlQuery": null,
    "sqlShell": false,
    "sqlFile": null,
    "commonTables": false,
    "commonColumns": false,
    "commonFiles": false,
    "udfInject": false,
    "shLib": null,
    "fileRead": null,
    "fileWrite": null,
    "fileDest": null,
    "osCmd": null,
    "osShell": false,
    "osPwn": false,
    "osSmb": false,
    "osBof": false,
    "privEsc": false,
    "msfPath": null,
    "tmpPath": null,
    "regRead": false,
    "regAdd": false,
    "regDel": false,
    "regKey": null,
    "regVal": null,
    "regData": null,
    "regType": null,
    "trafficFile": null,
    "answers": null,
    "batch": true,
    "base64Parameter": null,
    "base64Safe": false,
    "binaryFields": null,
    "charset": null,
    "checkInternet": false,
    "cleanup": false,
    "crawlDepth": null,
    "crawlExclude": null,
    "csvDel": ",",
    "dumpFormat": "CSV",
    "encoding": null,
    "eta": false,
    "flushSession": false,
    "forms": false,
    "freshQueries": false,
    "googlePage": 1,
    "harFile": null,
    "hexConvert": false,
    "outputDir": null,
    "parseErrors": false,
    "postprocess": null,
    "preprocess": null,
    "repair": false,
    "saveConfig": null,
    "scope": null,
    "skipHeuristics": false,
    "skipWaf": false,
    "testFilter": null,
    "testSkip": null,
    "webRoot": null,
    "alert": null,
    "beep": false,
    "dependencies": false,
    "disableColoring": true,
    "listTampers": false,
    "offline": false,
    "purge": false,
    "resultsFile": null,
    "tmpDir": null,
    "unstable": false,
    "updateAll": false,
    "wizard": false,
    "verbose": 1,
    "dummy": false,
    "disablePrecon": false,
    "profile": false,
    "forceDns": false,
    "murphyRate": null,
    "smokeTest": false,
    "api": true,
    "taskid": "27262c27d20707dc",
    "database": "/tmp/sqlmapipc-qgylcj8p"
  }
}
```