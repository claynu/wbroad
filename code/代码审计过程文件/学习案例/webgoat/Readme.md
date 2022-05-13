### webgoat 案例学习

---

``` 审计代码发现每个类型的漏洞是独立项目 具体技术在对应模块描述 8.2.0 依赖jdk15运行环境需要大于等于15``` 

1. 根据目录结构和`pom.xml`确定项目的三方包为maven管理的 检查pom文件 框架整体是采用spring boot 
   1. ![pom.xml](F:\文档\wbroad\code\代码审计过程文件\学习案例\webgoat\文档\img\pom.png)

#### 0x01 sqli

> ```java
> java.sql.Connection 敏感函数 createStatement() 有sql注入风险
> ```

1. lesson2  
   1. ``` # 第2题是一个sql基础题 根据题目示例表查出 Bob Franco的部门信息```
   2. 抓包确定接口地址 根据 attack2 为关键字进行全局搜索，java 中
      1. ![](F:\文档\wbroad\code\代码审计过程文件\学习案例\webgoat\文档\img\sqli_attack2.png)
   3. 全局搜索
      1. ![代码ctrl+shift+f全局搜索](F:\文档\wbroad\code\代码审计过程文件\学习案例\webgoat\文档\img\idea_sqli_attack2.png)
      2. ![](F:\文档\wbroad\code\代码审计过程文件\学习案例\webgoat\文档\img\idea_sqli_attact2_code.png)
   4. 审计代码发现 后端对输入未进行过滤，输出需要校验department 为Marketing ，sql为用户任意输入，需要回显 payload 为 `select DEPARTMENT,database(),user(),1,1,1 from employees where userid = 37648` ，或者是通过left join enployees中的回显校验department 进行连接查询，不需要回显可以执行任意sql
   5. 1. ![](F:\文档\wbroad\code\代码审计过程文件\学习案例\webgoat\文档\img\result_attack01.png)
      2. ![](F:\文档\wbroad\code\代码审计过程文件\学习案例\webgoat\文档\img\webgost_sqli02_check.png)



2. 由于webgoat 的sqli从代码审计角度较为简单 直接做第一系列的最后一题
   1. ![代码](F:\文档\wbroad\code\代码审计过程文件\学习案例\webgoat\文档\img\code_sqli010.png)
   2. 根据代码可以判断 对输入没有过滤，payload 可为 `' ;  delete from access_log --`  其中`';`闭合前面语句 后跟一句删除日志语句即可
   3. 验证通过
      1. ![验证](F:\文档\wbroad\code\代码审计过程文件\学习案例\webgoat\文档\img\webgoat_sqli10_check.png)