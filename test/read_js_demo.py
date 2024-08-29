import os
import subprocess
from functools import partial
import requests
os.environ['PYTHONIOENCODING'] = 'utf-8'
subprocess.Popen = partial(subprocess.Popen, encoding="utf-8")
import execjs

# 定义远程JavaScript代码的URL
js_urls = [
    'http://25.75.2.2:20080/display/views/common/common.js',
    'http://25.75.2.2:20080/display/views/encryptjs/js/SM.js',
    'http://25.75.2.2:20080/display/views/encryptjs/js/smtransfer.js'
]
# 获取并合并JavaScript代码
js_code = ''
for url in js_urls:
    response = requests.get(url)
    if response.status_code == 200:
        js_code += response.text


# 执行JavaScript代码
js_code = 'var $ = jQuery; ' + js_code
ctx = execjs.compile(js_code)

arg1 = '448041ae214fa125d6e6706ddca1599bdb40cc90783ad6206f617bbce3198ceae7709d53d0337408de64c767e5310444'
arg2 = 'a2de69089fd464813dd9d4523836bd14'
# 假设远程JavaScript代码中定义了一个名为`myFunction`的函数
# 调用这个函数
result = ctx.call('SG_sm4decrypt', arg1, arg2)  # 替换arg1, arg2为你的参数
print(result)