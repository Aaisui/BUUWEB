# BUU WEB题目整合

目前截止于截止于2021年10月30日，本人是web狗，所以就只截取了web方向的题目，带有强烈的主观意识判断，只是为了方便学弟学习使用，其他师傅们仅供参考即可。



以主要考点为主来统计。重申一下，根据笔者是根据自己的水平进行归纳的（笔者也就是个普通的大三学生），所以带有很强烈的主观印象，仅供参考



+ 简单 当前中大型赛事中基本不会出现，一般是新生赛的题目，作为初学者学习的题目
+ 签到  当前中大型赛事中作为签到出现，考点可能不会那么露骨，但是一般比赛中很多人都能做出来
+ 中等 中大型赛事作为中等题目出现，一般会有20-30队伍解出
+ 困难 作为困难题目出现，一般比赛中可能几个解甚至0解
+ 脑洞 带有强烈主观印象！！！师傅们看看就好。



笔者没有做过题目且没有找到WP的题目在最下面

## 代码审计：

### 简单

+ [HCTF 2018] WarmUp 难度：简单 知识点：初步的代码审计和文件包含
+ [BJDCTF2020]Mark loves cat 简单的代码审计，变量覆盖

### 签到

+ [HCTF 2018]admin 中等难度的题目，解法较多，分别有jwt伪造，条件竞争和unicode欺骗
+ [ZJCTF 2019]NiZhuanSiWe 基础的代码审计，解法较多，php伪协议
+ [BJDCTF2020]EasySearch 除了注入以外还会有Apache SSI 远程命令执行漏洞
+ [HarekazeCTF2019]encode_and_encode 编码绕过
+ [SUCTF 2019]EasyWeb 当年比较难的题目，现在这些考点被干碎了再出现就只能做签到了
+ [安洵杯 2019]不是文件上传 介乎于签到和中等之间，多个考点重合在一起了
+ [N1CTF 2018]eating_cms 
+ [PASECA2019] honey_shop 读取环境变量，介乎于签到和中等之间
+ Phuck2
+ [网鼎杯 2020 总决赛]Game Exp
+ 

### 中等

+ [De1CTF 2019]SSRF Me Flask 字符串拼接带来的安全问题
+ [HFCTF2020]EasyLogin jwt伪造
+ [SCTF2019]Flag Shop ruby 代码审计
+ [DDCTF 2019]homebrew event loop 逻辑漏洞
+ [XDCTF 2015]filemanager 
+ [PwnThyBytes 2019]Baby_SQL 
+ [SWPUCTF 2016]Web blogsys 哈希拓展攻击，逻辑漏洞
+ [PWNHUB 公开赛 2018]傻 fufu 的工作日 加解密逻辑最好自己能够掌握。
+ [CISCN2019 东北赛区 Day2 Web3]Point System
+ [HBCTF2017]大美西安
+ [N1CTF 2018]easy_harder_php soap_ssrf 非常经典的题目
+ [Zer0pts2020]notepad python反序列化

### 困难

+ [网鼎杯 2020 半决赛]faka  中等偏难
+ [RoarCTF 2019]PHPShe
+ [护网杯 2018]easy_laravel
+ [HMBCTF 2021]EzLight 红帽杯就3解还是几解我记得。
+ [HITCON 2017]Baby^h Master PHP  Apache-prefork模型(默认模型)在接受请求后会如何处理,首先Apache会默认生成5个child server去等待用户连接, 默认最高可生成256个child server, 这时候如果用户大量请求, Apache就会在处理完MaxRequestsPerChild个tcp连接后kill掉这个进程,开启一个新进程处理请求
+ [CISCN2019 总决赛 Day2 Web2]Laravel File Manager 参考文章：https://blog.szfszf.top/article/39/ 也是国赛经典不让人做
+ Real World CTF 2018 Bookhub

​		

### 脑洞

+ [羊城杯 2020]Blackcat 要听歌的WEB题目== 2020🐏城杯的题目感觉..



## SSTI：

### 简单

+ [CSCCTF 2019 Qual]FlaskLight



### 签到

+ [BJDCTF2020]Cookie is so stable twig模板注入
+ [WesternCTF2018]shrine  想方设法获取config
+ [CISCN2019 华东南赛区]Web11 smarty模板注入
+ [BJDCTF2020]The mystery of ip  简单的flask注入
+ [GYCTF2020]FlaskApp debug模式一定条件下可以窃取出来pin码命令执行，但是题目过滤的不够严格导致可以直接打，比签到难一点
+ [pasecactf_2019]flask_ssti 编码绕过
+ [GWCTF 2019]你的名字
+ [CISCN2019 总决赛 Day1 Web3]Flask Message Board



### 中等

+ [护网杯 2018]easy_tornado 因为框架比较冷门，如果不看WP的话需要自己手动翻手册，我觉得算中上偏难的题目。
+ [CISCN2019 华东南赛区]Double Secret 国赛半决赛因为大家互相出题所以都互相恶心，这题整个MD4，线下环境怎么打？
+ 

### 困难

+ [QWB2021 Quals]托纳多

### 脑洞

+ [RootersCTF2019]I_<3_Flask 用name注入。？怎么想到的

## SQL注入：

### 简单

+ [极客大挑战 2019]LoveSQL 基础的注入题目
+ [极客大挑战 2019]BabySQL 基础的注入题目
+ [极客大挑战 2019]HardSQL 报错注入以及需要绕过过滤
+ [GXYCTF2019]BabySQli union select 可以用于构造数据
+ [CISCN2019 华北赛区 Day2 Web1]Hack World 简单的盲注
+ [SWPU2019]Web1 =题目难度取决于你有耐心去测字段数
+ [WUSTCTF2020]颜值成绩单 题目非常卡，应该是因为CDN的缘故=。=
+ [b01lers2020]Life on Mars
+ October 2019 Twice SQL Injection 简单题目
+ [RootersCTF2019]babyWeb

### 签到

+ [极客大挑战 2019]FinalSQL
+ [CISCN2019 华北赛区 Day1 Web5]CyberPunk 
+ [RCTF2015]EasySQL
+ [SUCTF 2019]EasySQL 堆叠注入题目，基础
+ [网鼎杯 2018]Comment hex对无法直接注入的内容加密一下
+ [GYCTF2020]Ezsqli 无列名注入
+ [NCTF2019]SQLi regexp
+ [网鼎杯2018]Unfinish hex
+ [RoarCTF 2019]Online Proxy
+ [SWPU2019]Web4 
+ [Black Watch 入群题]Web 
+ [SUCTF 2018]MultiSQL
+ [BSidesCF 2019]Sequel 没有过滤的sqlite注入
+ [SWPU2019]Web6 [with rollup](https://www.cnblogs.com/20175211lyz/p/12285279.html#sql注入中的with-rollup)注入
+ [GWCTF 2019]blog 注入部分是签到难度的，后面会涉及到cbc翻转
+ 



### 中等

+ [强网杯 2019]随便注 考点是堆叠注入
+ [GYCTF2020]Blacklist 堆叠注入
+ [网鼎杯 2018]Fakebook 有一点反序列化的内容
+ [CISCN2019 总决赛 Day2 Web1]Easyweb 预期解比较难，需要伪造admin的密钥
+ [PwnThyBytes 2019]Baby_SQL
+ 2021祥云杯]Package Manager 2021 mongdb注入
+ [GKCTF 2021]hackme mongdb注入，不过这题难点不在这里
+ kzone unicode绕过
+ [SCTF 2018]ZhuanXV

### 困难

+ [HarekazeCTF2019]Sqlite Voting 中等偏难，sqlite注入
+ [De1CTF 2019]Giftbox 这题没有做过，
+ [Black Watch 入群题]Web2 sql注入部分不给hint真的很难想得到
+ [D3CTF 2019]Showhub insert on duplicate key update 注入
+ [hitcon2017] Sql-so-hard 复现  max_allowed_packet

## 文件上传：

### 简单

+ [极客大挑战 2019]Upload 基础的文件上传，php5环境可以利用script绕过标签限制
+ [ACTF2020 新生赛]Upload 基础的文件上传
+ [MRCTF2020]你传你🐎呢 基础的文件上传绕过
+ [GXYCTF2019]BabyUpload 基础的文件上传绕过

### 签到

+ [WUSTCTF2020]CV Maker 
+ [RoarCTF 2019]Simple Upload 
+ [HarekazeCTF2019]Avatar Uploader 2



### 中等

+ [SUCTF 2019]CheckIn .user.ini 除此之外还需要尝试绕过函数check
+ [XNUCA2019Qualifier]EasyPHP
+ [SWPU2019]Web3 jwt伪造+zip下载
+ [FireshellCTF2020]ScreenShoot
+ [JMCTF 2021]GoOSS 盲注解法很有意思=。=！

### 困难

+ 2019 0CTF/TCTF wallbreaker easy 恶意so文件上传
+ [QWB2021 Quals]托纳多
+ l33t-hoster
+ [BBCTF2020]imgaccess2 



## 文件包含

纯文件包含很难出的很难

### 简单

+ [极客大挑战 2019]Secret 基础题目。
+ [RoarCTF 2019]Easy Java java题目=。=
+ [BSidesCF 2020]Had a bad day 文件包含

### 签到：

+ [SUCTF 2019]Pythonginx 该题为一个[tricks](https://i.blackhat.com/USA-19/Thursday/us-19-Birch-HostSplit-Exploitable-Antipatterns-In-Unicode-Normalization.pdf),其中有关于python的字符的安全问题，除此之外还有第二种解法
+ [NPUCTF2020]ezinclude 临时文件包含
+ [FireshellCTF2020]Caas C语言

### 中等

+ [WMCTF2020]Make PHP Great Again
+ [CISCN2021 Quals]upload 当时真的好难，主要是国赛这次这个题目只给做几个小时，不然感觉很多人是可以做出来的
+ 

### 困难

+ [WMCTF2020]Web Check in 2.0
+ [WMCTF2020]Web Check in 一个题目，这个有非预期
+ [CISCN2021 Quals]filter yii2 laravel LFI 的CVE改的



## 命令执行

### 简单

+ ACTF2020 新生赛]Exec 基础的命令执行
+ [BUUCTF]Easybypass 很少的过滤

### 签到

+ [GXYCTF2019]Ping Ping 
+ [BUUCTF 2018]Online Tool escapeshellarg()和escapeshellcmd() 在一起会有问题。
+ [网鼎杯 2020 朱雀组]Nmap 和上题一样的考点
+ [极客大挑战 2019]RCE ME 无字母getshell，同时进行disable_function绕过
+ [FBCTF2019]RCEService 正则字符串回溯绕过
+ [红明谷CTF 2021]write_shell 
+ [羊城杯2020]easyphp
+ [RCTF 2019]Nextphp
+ CSAWQual 2016]i_got_id



### 中等

+ [GYCTF2020]EasyThinking  thinkphp6.0 任意文件操作

### 困难

+ [蓝帽杯 2021]One Pointer PHP suid提前，fsockopen绕过，（据说原本是个webpwn？
+ [N1CTF2020]DockerManager 
+ [羊城杯 2020]Break The Wall webpwn？
+ HITCON 2015 BabyFirst  orange的这种极限绕过的题都觉得眼界大开
+ [HITCON 2017]Babyfirst-Revenge
+ [HITCON 2017]Babyfirst-Revenge-V2
+ [CISCN2019 总决赛 Day1 Web5]Markdown Note 恶心人的题目，带了逆向，也是现场不想让你做的题目

## 代码执行



### 简单

+ [极客大挑战 2019]Knife 蚁剑
+ [SUCTF 2018]GetShell 无字母getshell

### 签到

+ [GXYCTF2019]禁止套娃 过滤绕过。
+ [安洵杯 2019]easy_web
+ [HITCON 2017]SSRFme perl脚本漏洞
+ [SUCTF 2018]GetShell 无字母getshell
+ [ISITDTU 2019]EasyPHP 命令执行取反，绕过

### 中等

+ [RoarCTF 2019]Easy Calc 利用字符串解析差异，但是我觉得这样解释有点过于脑洞，可能题目出的时候是有hint的，直接猜想是很难猜想出来的。所以这道题的出题人考点可能在于http走私
+ [BJDCTF2020]EzPHP 恶心的一批，大杂烩了属于是
+ [HFCTF2020]JustEscape  又有PHP又有JS，VM2沙箱逃逸
+ [De1CTF 2019]ShellShellShell
+ [D3CTF 2019]EasyWeb

### 困难

+ [CISCN 2019 初赛]Love Math 经典题目了，这个题目作为第一次出现的话真的很难，建议看[赵总视频学习](https://www.bilibili.com/video/BV1pE411f7DN?spm_id_from=333.999.0.0)
+ [NESTCTF 2019]Love Math 2 上面那道题目的加强版本
+ ctf473831530_2018_web_virink_web fpm未授权访问和rsync

## 反序列化

### 简单

+ [极客大挑战 2019]PHP 反序列化，wakeup绕过

+ [MRCTF2020]Ezpop 简单的pop

+ [NPUCTF2020]ReadlezPHP 动态函数

+ [EIS 2019]EzPOP 

  

### 签到

+ [网鼎杯 2020 青龙组]AreUSerialz 反序列化，弱类型比较
+ [网鼎杯 2020 朱雀组]phpweb 简单的反序列化命令执行
+ [安洵杯 2019]easy_serialize_php 反序列化逃逸
+ [SWPUCTF 2018]SimplePHP phar反序列化
+ [CISCN2019 华北赛区 Day1 Web1]Dropbox  phar反序列化
+ [GXYCTF2019]BabysqliV3.0 
+ [2020 新春红包题] 
+ [极客大挑战 2020]Greatphp 原生类的利用
+ [watevrCTF-2019]Pickle Store python 反序列化
+ [SUCTF 2019]Upload Labs2 原生类反序列化
+ [网鼎杯 2020 总决赛]Game Exp

### 中等

+ [0CTF 2016]piapiapia 重量级，这题居然是16年的题目，放到现在感觉也不算特别简单的题目，介乎中等之间
+ [CISCN2019 华北赛区 Day1 Web2]ikun python反序列化，jwt伪造
+ [强网杯 2019]Upload 反序列化
+ bestphp's revenge 反序列化引擎带来的问题
+ [HarekazeCTF2019]Easy Notes 和上面一道题是一个考点
+ [HFCTF 2021 Final]easyflask python 反序列化
+ [MRCTF2020]Ezpop_Revenge 简单的POP 打SSRF
+ [红明谷CTF 2021]EasyTP thinkphp3反序列化读取任意文件
+ [D3CTF 2019]EzUpload



### 困难

+ [CISCN2019 总决赛 Day1 Web4]Laravel1 当时应该是0day出题，纯自己做也是比较麻烦的
+ [安洵杯 2019]iamthinking 1day出的题，纯自己挖反序列化也是困难的、
+ [NCTF2019]phar matches everything phar反序列化漏洞+SSRF漏洞+PHP-FPM未授权访问漏洞。
+ [RoarCTF 2019]PHPShe
+ 虎符2021线下 tinypng 这道题很有意思，绕过姿势很多，需要详细做



### 脑洞

+ [羊城杯 2020]EasySer



## 脚本编写

### 简单

### 签到

+ [GXYCTF2019]StrongestMin 

### 中等

+ [强网杯 2019]高明的黑客 
+ [BSidesCF 2020]Cards
+  [b01lers2020] Scrambled

### 困难

+ [QWB2021 Quals]popmaster



## Node

### 简单

+ 

### 签到

+ [NPUCTF2020]验证🐎 稍等比签到难

### 中等

+ [GYCTF2020]Ez_Express 介乎于签到和中等之间，主要是这里的原型链污染出现过了所以不会算难
+ [GYCTF2020]Node Game node8 unicode编码问题导致的CRLF
+ [2021祥云杯]secrets_of_admin 代码逻辑问题
+ [网鼎杯 2020 半决赛]BabyJS 
+ [2021祥云杯]cralwer_z
+ [XNUCA2019Qualifier]HardJ 当年很难，但是在2021年ejs原型链污染这个大家都会了
+ [RootersCTF2019]notifyxapi
+ [GKCTF 2021]easynode 我出的垃圾题目

### 困难

+ [HITCON 2016]Leaking node沙箱逃逸（纯自己做的话就很难了，不过exp现在满天飞了
+ [RCTF2019]calcalcalc 
+ [De1CTF 2019]9calc
+ [STARCTF2019]996game

## XXE

### 简单

+ [NCTF2019]Fake XML cookbook 最基础的XXE

  

### 签到

+ [NCTF2019]True XML cookbook 利用xxe做内网探测

+ [CSAWQual 2019]Web_Unagi utf编码绕过
+ [BSidesCF 2019]SVGMagic svg图片xxe
+ [NPUCTF2020]ezlogin xpath注入
+ [FireshellCTF2020]Cars

### 中等

+ [GoogleCTF2019 Quals]Bnv-XXE学习记录 现在不算了=。=
+ [SUCTF 2018]Homework



## XSS

### 简单

+ 

### 签到

+ [GWCTF 2019]mypassword
+ [GKCTF 2021]CheckBot GKCTF0解题目，难度不用我多说了吧 考的是个tricks

### 中等

+ [CISCN2019 华东北赛区]Web2

+ [网鼎杯 2020 青龙组]notes

+ [Zer0pts2020]musicblog

+ [安洵杯 2019]cssgame xs-lerk 通过css的正则带出flag

+ math-is-fun1 css外带

  

### 困难

+ [SCTF2019]Math-IS-Fun-2 上面那道题的加强版？实际上没有反看到WP
+ [QWB2021 Quals]HardXSS hardxxe【

## JAVA

### 简单

### 签到

### 中等

+ [网鼎杯 2020 青龙组]filejava
+ [网鼎杯 2020 朱雀组]Think Java
+ [GKCTF 2021]babycat
+ [红明谷CTF 2021]JavaWeb 一年出现三次的题目
+ [GKCTF 2021]babycat-revenge
+ [WUSTCTF2020]Train Yourself To Be Godly tomcat题目CVE hackhat的tricks
+ [羊城杯 2020]A Piece Of Java java反序列化
+ [NPUCTF2020]EzShiro 
+ [SCTF 2018]ZhuanXV

### 困难

+ 

## SSRF

### 简单

### 签到

+ [De1CTF 2019]SSRF Me Flask 字符串拼接带来的安全问题

### 中等

+ [网鼎杯 2020 玄武组]SSRFMe 打主从redis
+ [SWPUCTF 2016]Web7
+ [GKCTF 2021]hackme



### 困难

+ [虎符CTF 2021]Internal System
+ [CISCN2019 总决赛 Day1 Web2]Homebrew Dubbo



## Basic

​	记录在这里的题目大部分比较简单且不是很好归为大类

+ [极客大挑战 2019]Havefun 传参
+ [极客大挑战 2019]Http 各种头伪造
+ [ACTF2020 新生赛]BackupFile 文件泄露备份
+ [极客大挑战 2019]BuyFlag 弱类型比较、
+ [BJDCTF2020]Easy MD5 md5比较
+ [WUSTCTF2020]朴实无华 MD5绕过
+ [MRCTF2020]PYWebsite -wp 简单的伪造
+ [BSidesCF 2019]Kookie 简单题目
+ [b01lers2020]Welcome to Earth
+ [watevrCTF-2019]Cookie Store
+ [极客大挑战 2020]Roamphp1-Welcome
+ [RootersCTF2019]ImgXweb jwt伪造
+ [BSidesCF 2019]Pick Tac Toe
+ [BSidesCF 2020]Hurdles
+ virink_2019_files_share
+ [极客大挑战 2020]Roamphp4-Rceme



## Tricks/CVE

记录在这里的都是用tricks/CVE出的题目

+ [MRCTF2020]Ez_bypass
+ [GWCTF 2019]我有一个数据库 phpmyadmin4.8.0-4.8.1存在CVE
+ [ASIS 2019]Unicorn shop  unicorn 编码绕过
+ [BSidesCF 2019]Futurella misc跑到web来了、。
+ [MRCTF2020]套娃
+ [GWCTF 2019]枯燥的抽奖 伪随机数
+ [Zer0pts2020]Can you guess it? php5.3：basename()函数漏洞
+ **[网鼎杯 2020 白虎组]PicDown**  /proc/self 下的文件很重要
+ [MRCTF2020]Ezaudit 伪随机数

+ [HarekazeCTF2019]Avatar Uploader 1 misc题目跑web里面了
+ [GKCTF 2021]easycms ezcms cve复现
+ [SUCTF 2018]annonymous
+ [BSidesCF 2019]Mixer ecb加密、
+ [NPUCTF2020]web🐕
+ easyweb tomcat cve复现
+ [BSidesCF 2020]Bulls23 流量分析，BUU好像挂了
+ [极客大挑战 2020]Cross  渗透题目，**其实很有意思的一道题目**【但是不知道为什么做的人很少
+ [HarekazeCTF2019]One Quadrillion tricks 文章：https://nkhrlab.hatenablog.com/entry/2019/05/19/224643





## Windows

### 中等

+ [Windows]LFI2019

### 困难

+ [HITCON 2019]Buggy_Net NET4.0 net题目，hitcon的题目感觉都挺难的【
+ [Windows][HITCON 2018]Why-So-Serials



## WEBPWN

webpwn放出来就不可能简单

### 困难

+ [De1CTF 2019]cloudmusic_rev
+ [CISCN2019 总决赛 Day1 Web1]滑稽云音乐 上面那道题是根据这道题改变的
+ [羊城杯 2020]Break The Wall webpwn？
+ 2019 0CTF/TCTF wallbreaker easy 恶意so文件上传



## Break/Fix

+ [网鼎杯 2020 半决赛]AliceWebsite
+ [网鼎杯 2020 半决赛]BabyJS
+ [HFCTF 2021 Final]hatenum sql注入题目
+ [HCTF2018]final Web1 参考小西师傅的文章:https://moxiaoxi.info/ctf/2018/12/31/HCTFfinal/



## GO

### 困难

+ [RoarCTF 2019]Dist

## 未知难度

+ [CSCCTF 2019 Final]lofiai

+ [WMCTF2020]webcheckin 有好多checkin啊。。
+ [OGeek2019]Easy Real World 2
+ [INS'hAck 2019]Atchap、
+ [纵横杯1st 线下赛]upload
+ [NCTF2017]Be admin cbc反转攻击
+ Unkonwn Web 1
+ [SWPU2019]Web2 php-fpm的unix套接字来进行绕过openbase_dir和绕过disable_function
+ [N1CTF2020]Easy TP5
+ [N1CTF2020]Zabbix-fun 
+ [BBCTF2020]note
+ NodeProxy
+ [SWPU2019]Web5
+ [OGeek2019]Enjoy Yourself
+ [CISCN2019 华东北赛区]Web6 
+ [MRCTF2020]Not So Web Application
+ [BBCTF2020]analytics
+ [Midnightsun CTF Quals 2019]Bigspin

后面两页的题目几乎都没有WP了，我想很有可能就这么被淹没在时间长河中了。笔者统计至此有点疲倦了，故将不再一个个尝试搜索WP统计，姑且都当作未知难度的题目，原本是想截个图收工的，但是想到出题人的师傅们出题时候的心情，还是一个个的记录下来了，说不定以后自己也会去做做看呢 :)。

+ [SUCTF 2018]HateIT
+ [Balsn2019]Images and Words

+ [BSidesCF 2019]MainFrame
+ [SCTF2018]BabySyc
+ TheMatrix 
+ final Web2
+ [FBCTF2019]HR Module
+ [CSCCTF 2019 Final]ZlipperyStillAlive
+ [WMCTF2020]gogogo
+ [极客大挑战 2020]Roamphp5-FighterFightsInvincibly
+ [HCTF 2017]Deserted place
+ [StarCTF2019]EchoHub
+ [CISCN2019 华东南赛区]Web9
+ [XNUCA2019Qualifier]Blog Revenge
+ [watevrCTF-2019]HTJP
+ [WMCTF2020]easycoherence
+ [网鼎杯 2020 总决赛]Vulnfaces
+ [纵横杯1st 线下赛]easyphp
+ [34C3CTF 2017]urlstorage **python** **XSS** **CSRF**

+ SEAFARING xss
+ [SuperFish9 2019]XSS xss
+ [XNUCA2019Qualifier]Easy Crypto 
+ [FBCTF2019]Secret Note keeper

+ [INS'hAck 2019]bypasses-everywhere
+ [INS'hAck 2019]bypasses-everywhere-2
+ [OGeek2019]Check In
+ [D3CTF 2019]BabyXSS
+ [N1CTF 2019]babyphoto
+ [Balsn2019]RCE auditor
+ [watevrCTF-2019]NewPwd
+ [BSidesCF 2019]FlagSrv
+ [WMCTF2020]CFGO
+ [极客大挑战 2020]Roamphp6-flagshop 这道题目应该是环境出了问题



至此，BUU上所有的WEB的题目笔者已经粗略的进行了分类，希望能在以后的时间里对各位小师傅们的学习起到帮助