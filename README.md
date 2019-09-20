知识图谱+网络安全
====
# Knowledge-Graph-Analyze
## 尝试1：
Bro和Snort的初步结果存入知识图谱，如网络包、网络底层事件等。知识图谱在这些数据的基础上进行分析。  
问题：  
具体是做什么样的分析呢，分析出什么结果？  
老师提及的“多步攻击”？  
知识图谱中的数据的存储格式是不是要作出改变，以适应“分析”的要求？  
关于网络底层事件：  
网络基本事件，Bro会生成很多日志文件，其中大多数是以协议的名称命名的（其内容基本是与该协议相关的流量内容）。但是也有比较特殊的日志文件，比如notice.log，我们可以定制该文件的内容（通过添加notice类型的方式），姑且认为notice.log文件中记录的内容就是所谓的网络基本事件。  
conn.log中存放网络中连接的日志，其实连接建立也是一种事件，是不是被Bro整理为日志输出的内容，都属于事件的范畴？  
关于网络包：  
网络包应该是网络流量最原始的状态，没有经过上层分析。Snort在Packet Logger模式下，记录的就是网络数据包。  
关于知识图谱的分析、推理功能：  
参考《网络空间安全防御与态势感知》的第8章，要对网络中的事件坐初步的分析、推理需要一个”本体模型“，这里提及了OWL模型。所以，我们的数据是不是也需要经过一番处理，转换成OWL模型的数据，方便分析、推理呢？  
关于知识图谱的存储：  
我们目前将知识存储在MYSQL数据库中，这种传统的关系型数据的存储与知识图谱所需的语义存储相去甚远。考虑使用D2RQ将关系型数据转换为RDF表示的数据。  

## 数据集选取
考虑DARPA的[LLS_DDOS](archive.ll.mit.edu/ideval/data/2000/LLS_DDOS_1.0.html)，这是一个DDOS攻击的数据集，它将攻击分为五个阶段[^2]:  
(1) 预探测网络（IPSweep）;  
IPsweep of the AFB from a remote site  
(2) 端口扫描，确定主机的脆弱信息（PortScan）;
Probe of live IP's to look for the sadmind daemon running on Solaris hosts  
(3) 获得管理员权限（FTPBufOverflow）;  
Breakins via the sadmind vulnerability, both successful and unsuccessful on those hosts  
(4) 安装特洛伊Mstream DDOS木马软件（UploadSoftware）;  
Installation of the trojan mstream DDoS software on three hosts at the AFB  
(5) 借助被控制的主机对远程服务器发动DDOS攻击（DDOSAttack）;  
Launching the DDoS  

[^2]:胡倩.基于多步攻击场景的攻击预测方法[J].计算机科学,2019,46(S1):365-369.
