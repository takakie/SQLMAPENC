---
title: SQL注入请求包自定义加解密
categories: 网络安全
tags: 
  - SQLMAP
  - 渗透测试
  - SQL注入
  - 安全开发
ai: 
cover: 
date: 2024-08-24
---

# 1.简介

- 该项目主要通过修改SQLMAP源代码对SQLMAP文件读入的request进行解密，和对注入payload后发包时的请求进行加密，以此来对存在请求加密的WEB网站进行SQL注入扫描的目的

# 2.代码结构

- 主要是修改了三处代码

- 第一处 请求参数的解密 

- 原代码，代码路径 lib/core/option.py

  ```python
  for target in parseRequestFile(requestFile):
      url = target[0]
      if url not in seen:
          kb.targets.add(target)
          if len(kb.targets) > 1:
              conf.multipleTargets = True
              seen.add(url)
  ```

- 更改后代码

  ```python
  from plugins.requestende.requesthandler import decrypt_request_handler
  
  for target in parseRequestFile(requestFile):
      # 请求包解密 TODO
      plain_target = decrypt_request_handler(target)
      # 将for 中的所有target替换为了plain_target
      url = plain_target[0]
      if url not in seen:
          kb.targets.add(plain_target)
          if len(kb.targets) > 1:
              conf.multipleTargets = True
              seen.add(url)
  ```

- 第二处代码 lib/request/connect.py

  if webSocket: 位置上方添加以下代码

  ```python
  from plugins.requestende.requesthandler import encrypt_request_handler
  
  url, post, headers = encrypt_request_handler(url, post, headers)
  ```

- 第三处代码 lib/request/connect.py

  在第二个getPage()函数中第二个 threadData.lastPage = page上方添加以下代码

  ```python
  from plugins.requestende.responsehandler import decrypt_response
  
  # 响应页面解密 TODO
  page = decrypt_response(page)
  ```



- 最后新增了三个新的代码文件在plugins/requestende目录下,

  分别是**encryptfunc.py**、**requesthandler.py**，**responsehandler.py**。

  

# 3.说明

- 项目代码主要是根据1.8 稳定版代码更改而来。

- 项目主要是在尽量不更改原代码逻辑的情况下，实现对请求的加解密处理。
- 因此如果SQLMAP代码更新，可以根据以上代码变更新版本的SQLMAP代码，以此来更新该项目。