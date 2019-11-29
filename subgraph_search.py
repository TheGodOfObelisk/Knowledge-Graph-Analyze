#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import subprocess
import json
import requests
import urllib
# 测试Restful API执行gremlin
# 垃圾,点和边要单独查?
# 把ui里脚本的g换成hugegraph.traversal()
# gremlin_srcipt = """hugegraph.traversal().V().hasLabel("attack_pattern_0")"""
# gremlin_srcipt = """hugegraph.traversal().V().hasLabel("attack_pattern_0")"""
# gremlin_srcipt = """hugegraph.traversal().E().hasLabel("attack_event_0")"""
# gremlin_srcipt = """hugegraph.traversal().V().group().by(label)"""
# gremlin_srcipt = """hugegraph.traversal().V().hasLabel('attack_pattern_0').out().has('pattern_node_id',within(1))"""
# gremline_for_pattern_0 = """'subGraph = g.E().hasLabel('icmp_echo_ping').subgraph('subGraph').cap('subGraph').next()
#                         sg = subGraph.traversal()
#                         sg.E()'"""
# url = "http://127.0.0.1:8080/gremlin?gremlin="
# url = url + gremline_for_pattern_0
# response = requests.get(url)
# print response.status_code
# print response.text

# Restful API例子
# url中的特殊字符编码规范:  https://www.w3cschool.cn/htmltags/html-urlencode.html

# http://localhost:8080/graphs/hugegraph/traversers/kout?source=%222:0%22&max_depth=1
# 从"2:0"点出发,一步可达的点集合,可以继续增加max_depth的值,当返回空时,max_depth=MAX_DISTANCE-1
# 用不着最短路径了,自带的最短路径用不了

# gremlin例子
# g.V().as('a').out('icmp_echo_ping').as('b').select('a','b')
# 由icmp_echo_ping类型的边相连的两个点的信息

# g.V().as('a').out('icmp_echo_ping').as('b').select('a','b').by('ip')
# 由icmp_echo_ping类型的边相连的两个点的ip的信息,

# g.V().where(out('icmp_echo_ping')).values('ip')
# 有icmp_echo_ping类型出边的点的ip值

# g.V().where(out('attack_event_0').count().is(gte(6))).values('pattern_node_id')
# 取出边类型为attack_event_0,且该类型出边条数大于等于6的点(的pattern_node_id值)

# g.V().where(__.not(out('icmp_echo_ping'))).where(__.in('icmp_echo_reply')).values('ip')
# 取出没有类型为icmp_echo_ping的出边,但是有icmp_echo_reply的入边的点(的ip)

# g.V().where(out('rpc_call').where(out('rpc_reply'))).values('ip')
# 取出有类型为rpc_call的出边,且接着这个出边,有类型为rpc_reply的第二跳出边的点(的ip)

# g.V('2:0').outE('attack_event_0').values('event_label')
# 取出从可疑点触发的攻击事件边的事件类型(会有重复),复杂一点,记下数量?
# g.E().hasLabel('attack_event_0').values('event_label')
# 攻击模式0下所有的边事件类型

# g.V('1:202.77.162.213').out().out().path()
# 从点202.77.162.213出发,连续两个出变的路线

# g.V().and(outE('icmp_echo_ping'), values('ip').is('202.77.162.213')).values('ts')
# 有icmp_echo_ping类型出边,且ip为202.77.162.213的点的ts值

# g.V().as('a').out('icmp_echo_ping').as('b').select('a','b')
# 取a->b的,边为icmp_echo_ping的所有a,b对

# g.V().group().by(bothE().count())
# 此方法可以把图中的所有点按照度进行分组,可用于取前k个节点(度由高到低)

# g.V().match(__.as('a').in('icmp_echo_ping').has('ip', '202.77.162.213').as('b'))
# 此方法是gremlin的模式匹配,满足则生成一个map<String, Object>,不满足则过滤掉
# 模式1: "a"对应当前节点,有icmp_echo_ping的入边
# 模式2: "b"对应节点"202.77.162.213"
# 效果: 得到从b出发的,且距离为1的所有节点对

# g.V().match(
#     __.as('a').out('icmp_echo_ping').as('b'),
#     __.as('b').in('rpc_call').as('c')).
#     where('a', neq('c')).
#     select('a','c').by('ip')
# 从某个节点a出发的icmp_echo_ping,到节点b,节点b有来自节点c的rpc_call的入边,where保证a和c

# g.V('1:202.77.162.213').match(
#     __.as('a').out('icmp_echo_ping').as('b'),
#     __.as('b').in('icmp_echo_reply').as('c')).
#     where('a', eq('c')).
#     select('a','b')
# 在本场景中也可以用,指定出发点的id,a等于c表示环

# g.V('2:0').bothE().otherV().simplePath().path()
# g.V('2:0').both().both().cyclicPath().path()


# 需要的gremline功能
# 在图sg中,取出其中所有满足某个边属性条件的,边

# 这里不好用Restful API执行,可以使用hugegraph-tool的gremlin-execute指令执行
# gremlin-execute: 同步执行
# --script 执行脚本看来不太行
# --file 执行文件中的脚本,脚本语句的前后依赖不能太多,不然运行非常慢
# gremlin-schedule: 异步执行

# gremlin执行流程:
# 1. 根据需求设置gremlin语句
# 2. 将gremlin写入脚本文件
# 3. cmd拼接脚本文件
# 4. hugegraph-tool执行脚本文件
# 5. 分析返回结果

# 子图匹配步骤:
# 1. 从攻击模式图中提取特征信息(攻击模式图按照0,1,2,3,...编号)
#    gremlin脚本文件或者Restful API获取标签为attack_event_n的的边集合
#    特征信息包括:0点出边事件类型,0点到其他点的最远距离,环信息(如何表示?)
# 2. 按边事件类型提取子图,得到边集合,去除不关心的边(数据过滤1))
#    gremlin提供了subgraph方法
#    各种事件类型缺一不可,这里搜的边事件类型是和0号节点直接相连的事件类型(相对重要)
#    比如0->1->2,1->2的事件可以在最后一步模式匹配的时候再关心(皮之不存,毛将焉附)
# 3. 分析边集合,按照TIME WINDOW进行初步筛选,去除过旧的边(数据过滤2)
#    本地数据分析,JSON格式的边数据
# 4. 从边集合中提取点集合,得到过滤后的子图(该子图怎么存储,计算?)
#    本地数据分析,JSON格式的边数据中提取点数据
#    难点:过滤后的子图如何存放?保留在本地的话,不方便做图计算.简单整理之后,存回图谱?按照一种新的模式存储.
#    过滤后的子图肯定不能再存,需要在gremlin脚本中以图变量形式存在
#    所以,上面3步必须一次到位
# 5. 在上一步的子图中,计算各节点的度,并按照从达到小的顺序对节点进行排序(度越大,可疑程度越高)
#    参考gremlin中与节点度相关的图计算接口
# 6. 将可疑节点序列对应攻击模式中的0号节点,限定范围匹配(从可疑节点开始,1跳,2跳)
hugegraph_bin_path = "/home/lw/hugegraph-tools-1.3.0/bin/"
project_path = "/home/lw/myKGA/"
gremline_file_name = "gremlin_scripts"
tool_command = "gremlin-execute"

def execute_command(cmd):
    sub = subprocess.Popen(cmd, shell = True, stdout = subprocess.PIPE)
    str1 = sub.stdout.read()
    sub.communicate()
    str1 = str1.decode()
    print str1
    return str1

def extract_max_distance(source_node_id):
    max_distance = 1
    url = "http://localhost:8080/graphs/hugegraph/traversers/kout"
    pms = {
        "source": "\"{source_node_id}\"",
        "max_depth": max_distance
    }
    url_encoded = urllib.urlencode(pms)
    # cmd = "curl " + url
    # print cmd
    print url_encoded
    r = requests.get(url, params=pms)
    print r.url
    print r.status_code
    return max_distance

if __name__ == '__main__':
    # cmd = hugegraph_bin_path + "hugegraph " + tool_command + " --file " + project_path + gremline_file_name
    # execute_command(cmd)
    MAX_DISTANCE = 1 # ok
    TIME_WINDOW = 0 # 自己设
    KEY_EVENTS = [] # 取和0点相连的attack_event_n的边的event_label属性, ok
    EVENT_CHAIN_PATHS = []
    EVENT_CHAIN_CYCLICPATHS = []
    K = 1 # 自己设
    # 从特征图中提取以下要素
    # 从可疑节点出发的匹配规则
    # K值(前K个可疑点),ok
    # 最大距离(限制匹配范围),ok
    # 环的处理(模式匹配/连续out匹配),环仍然要化为匹配规则
    source_node_id = "2:0" # 攻击特征图中的攻击节点
    MAX_DISTANCE = extract_max_distance(source_node_id)
    print "MAX_DISTANCE = " + str(MAX_DISTANCE)
    # 匹配规则的格式:
    # 可疑点出发,攻击事件链(思路,从攻击模式图中查找所有的事件链组合,重复也没事,链上每一步可能有不止一个事件(兼备,只要模式匹配能达到这个要求就行))



