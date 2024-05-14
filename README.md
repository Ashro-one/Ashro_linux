Linux通用应急响应脚本，适用大多数情况

目前在ubuntu、centos7、kali上均可以正常运行。其他未实验 可以提供报错，针对修改。

脚本执行后生成的文件解释：
danger_file.txt  脚本执行后的高危结果，对付看，结果需要经验分析，不要一股脑就认为风险项。

<img width="486" alt="danger_file" src="https://github.com/Ashro-one/Ashro_linux/assets/49979071/a27255a6-9a9d-45b7-b06b-13a945aa8f0a">

check_file文件夹--检查命令篡改
weibu_md5.py 通过脚本获取系统上的命令配置文件的MD5值到check_file/*.csv文件中，进行微步的威胁情报查询，需要配置脚本中的自己api。脚本执行后会在当前目录生成结果文件。是否命令篡改结果一目了然。

<img width="904" alt="weibu_md5" src="https://github.com/Ashro-one/Ashro_linux/assets/49979071/67966557-66b4-487a-8655-fbcdc2dff430">


webshell文件夹--检查可执行文件后门
执行脚本后会将当前系统中正在进行的进程其涉及到的可执行文件cp下来。dump下来沙箱检测即可。

log文件夹--会将/var/log/*文件夹内容打包成压缩包
Ashro_checkresult.txt   结尾的是脚本执行过程日志，这个比较友好可以从这里分析

<img width="509" alt="image" src="https://github.com/Ashro-one/Ashro_linux/assets/49979071/806d9e04-6890-401a-a2ad-11af64598e7c">

详细功能介绍:<br>
1.必须root权限运行<br>
2.收集IP地址信息<br>
3.查看正在登录的用户<br>
4.查看/etc/passwd<br>
5.检查是否存在超级用户<br>
6.空口令账户检测<br>
7.新增用户检查<br>
8.新增用户组检查<br>
9.检测sudoers文件中的用户权限<br>
10.使用 visudo 命令查找具有 NOPASSWD 权限的用户<br>
11.检查各账户下是否存在ssh登录公钥<br>
12.账户密码文件权限检测<br>
13.暴力破解攻击检测<br>
14.查询正在监听的端口<br>
15.检查建立的网络连接<br>
16.检查是否存在系统进程<br>
17.检测存在那些守护进程<br>
18.CPU和内存使用率最高的进程排查（超过20%）<br>
19.检查是否存在隐藏进程<br>
20.检查反弹shell类进程<br>
21.将进程对应的可执行文件保存到指定目录--webshell--沙箱检测<br>
22.系统命令hash值打包---威胁情报MD5对比<br>
23.检查正在运行的服务<br>
24.检查系统文件的权限变更（一周内）<br>
25.收集历史命令<br>
26.用户自定义启动项排查<br>
27.系统自启动项排查<br>
28.危险启动项排查<br>
29.系统定时任务分析<br>
30.用户定时任务分析<br>
31.检查最近24小时内有改变的文件（误报会很多）<br>
32.cpu情况分析（占用前5）<br>
33.日志分析<br>
34.日志审核是否开启<br>
35.打包日志（/var/log/*）全打包<br>
36.secure日志分析（登录成功。登录失败，新增用户组）<br>
37.message日志分析（传输文件情况）<br>
38.cron日志分析（定时下载、定时执行）<br>
39.btmp日志分析（错误登录日志）<br>
40.lastlog日志分析（最后一次登录日志）<br>
41.wtmp日志分析(历史登录本机用户)<br>
42.Alias 后门检测<br>
43.SSH 后门检测<br>
44.SSH Wrapper 后门检测<br>
45.检查 SSH 授权密钥文件是否包含可疑命令<br>
46.检查特定目录中是否存在可疑文件<br>
47.检查系统日志中是否包含可疑内容<br>
48.防火墙配置检测<br>


windows应急响应工具地<br>
https://github.com/FindAllTeam/FindAll/
