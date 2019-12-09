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

# http://localhost:8080/graphs/hugegraph/traversers/rings?source=%222:0%22&max_depth=2&direction=OUT
# 可以求从原点出发最大n步内的环路,hugegraph的Rings功能

# http://localhost:8080/graphs/hugegraph/traversers/rays?source=%222:0%22&max_depth=2&direction=OUT
# 根据起始顶点、方向、边的类型（可选）和最大深度等条件查找发散到边界顶点的路径,hugegraph的Rays功能

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
# 从点202.77.162.213出发,连续两个出边的路线

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

# subGraph = g.E().or(__.hasLabel('icmp_echo_ping'),
#                     __.hasLabel('icmp_echo_reply'))
#                     .subgraph('subGraph').cap('subGraph').next()
# sg = subGraph.traversal()
# sg.E()
# 多类型的边,生成的子图.即子图中既包含icmp_echo_ping类型的边,也包含icmp_echo_reply类型的边

# g.V("2:0").repeat(out()).times(2).path()
# 某点出发,out两次

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
    # print str1
    return str1

def extract_max_distance(source_node_id):
    print "获取攻击节点可达的最远距离..."
    max_distance = 1
    while(True):
        url = "http://localhost:8080/graphs/hugegraph/traversers/kout"
        pms = {
            "max_depth": max_distance
        }
        pms["source"] = "\"%s\""%source_node_id
        url_encoded = urllib.urlencode(pms)
        # cmd = "curl " + url
        # print cmd
        # print url_encoded
        r = requests.get(url, params = pms)
        # print r.url
        # print r.status_code
        # print type(r.content)
        tmp_dict = json.loads(r.content)
        end_while = False
        for key in tmp_dict:
            if key == "vertices" and tmp_dict[key] == []:
                max_distance -= 1
                end_while = True
        if end_while:
            break
        max_distance += 1
    return max_distance

def extract_key_events(pattern_num):
    print "获取关键事件..."
    tmp_events = set()
    pattern = "attack_event_" + str(pattern_num)
    with open("gremlin_scripts", "w") as f:
        line = """g.V().outE('{attack_event_num}').values('event_label')\n""".format(attack_event_num = pattern)
        f.write(line)
        f.close()
    cmd = hugegraph_bin_path + "hugegraph " + tool_command + " --file " + project_path + gremline_file_name
    result = execute_command(cmd)
    # print result
    lines = result.split('\n')
    # print lines
    for item in lines:
        if item != "" and item != "Run gremlin script":# Run gremlin script是hugegraph的输出
            tmp_events.add(item)
    return tmp_events

def extract_edgelabel_id(PATTERN_NUM):
    url = "http://localhost:8080/graphs/hugegraph/schema/edgelabels/"
    edgelabel = "attack_event_" + str(PATTERN_NUM)
    url = url + edgelabel
    r = requests.get(url)
    tmp_dict = json.loads(r.content)
    return tmp_dict["id"]

def extract_attack_event_by_edgeid(edge_id):
    url = "http://localhost:8080/graphs/hugegraph/graph/edges/"
    url = url + edge_id
    r = requests.get(url)
    tmp_dict = json.loads(r.content)
    return tmp_dict["properties"]["event_label"]

def extract_event_chain_paths(source_node_id, MAX_DISTANCE, PATTERN_NUM):
    print "提取攻击事件链(无环)..."
    tmp_paths = []
    # 攻击事件链结构
    # 可以先用Rays方法求出其到边界节点的所有可能路径,然后把路径转为事件链.因为是特征子图,计算量不会太大.
    # event(n1),event(n2),...,event(n3)
    url = "http://localhost:8080/graphs/hugegraph/traversers/rays"
    pms = {
        "max_depth": MAX_DISTANCE,
        "direction": "OUT"
    }
    pms["source"] = "\"%s\""%source_node_id
    # url_encoded = urllib.urlencode(pms)
    r = requests.get(url, params = pms)
    tmp_dict = json.loads(r.content)
    print tmp_dict
    print tmp_dict["rays"]
    # 根据路径确定边id,边id由两点id以及边标签id决定,所以选查出边标签id,最后拼出边id
    edgelabel_id = extract_edgelabel_id(PATTERN_NUM)
    for item in tmp_dict["rays"]:
        i = 0
        # print item["objects"][2]
        attack_event_sequence_arr = []
        attack_event_sequence = ""
        while i + 1 < len(item["objects"]):
            tmp_src = item["objects"][i]
            tmp_dst = item["objects"][i+1]
            # tmp_sec, tmp_dst是一小段路径
            edge_id = "S" + tmp_src + ">" + str(edgelabel_id) + ">>S" + tmp_dst
            print edge_id
            attack_event = extract_attack_event_by_edgeid(edge_id)
            attack_event_sequence_arr.append(attack_event)
            i += 1
        for e in attack_event_sequence_arr:
            attack_event_sequence = attack_event_sequence + e + ">"
        if attack_event_sequence not in tmp_paths:
            tmp_paths.append(attack_event_sequence)
    return tmp_paths

def extract_event_chain_cyclicpaths(source_node_id, PATTERN_NUM):
    print "提取攻击事件链(环路)..."
    # 先确定环路查找的最大深度
    url = "http://localhost:8080/gremlin"
    pms = {}
    tmp_paths = []
    edgelabel = "attack_event_" + str(PATTERN_NUM)
    pms["gremlin"] = "hugegraph.traversal().E().hasLabel(\"%s\").count()"%edgelabel
    # url_encoded = urllib.urlencode(pms)
    r = requests.get(url, params = pms)
    tmp_dict = json.loads(r.content)
    depth = tmp_dict["result"]["data"][0] # 保守起见,设为边个数
    pms.clear()
    # 使用rings方法查找环路
    url = "http://localhost:8080/graphs/hugegraph/traversers/rings"
    pms["source"] = "\"%s\""%source_node_id
    pms["max_depth"] = depth
    pms["direction"] = "OUT"
    # url_encoded = urllib.urlencode(pms)
    r = requests.get(url, params = pms)
    tmp_dict = json.loads(r.content)
    edgelabel_id = extract_edgelabel_id(PATTERN_NUM)
    for item in tmp_dict["rings"]:# 照抄上面的
        i = 0
        # print item["objects"][2]
        attack_event_sequence_arr = []
        attack_event_sequence = ""
        while i + 1 < len(item["objects"]):
            tmp_src = item["objects"][i]
            tmp_dst = item["objects"][i+1]
            # tmp_sec, tmp_dst是一小段路径
            edge_id = "S" + tmp_src + ">" + str(edgelabel_id) + ">>S" + tmp_dst
            print edge_id
            attack_event = extract_attack_event_by_edgeid(edge_id)
            attack_event_sequence_arr.append(attack_event)
            i += 1
        for e in attack_event_sequence_arr:
            attack_event_sequence = attack_event_sequence + e + ">"
        if attack_event_sequence not in tmp_paths:
            tmp_paths.append(attack_event_sequence)
    return tmp_paths

def extract_suspicious_nodes_from_datagraph(KEY_EVENTS, K):
    print "查找可疑点序列..."
    request_body = {
        "bindings": {},
        "language": "gremlin-groovy",
        "aliases": {}
    }
    orSequence = ""
    for i in KEY_EVENTS:
        orSequence = orSequence + "__.hasLabel(\"%s\")"%i + ","
    orSequence = orSequence[:-1] # 去除结尾的逗号
    # print orSequence
    line1 = "subGraph = hugegraph.traversal().E().or(" + orSequence + ").subgraph(\"subGraph\").cap(\"subGraph\").next()\n"
    line2 = "sg = subGraph.traversal()\n"
    line3 = "sg.V().group().by(bothE().count())\n"
    request_body["gremlin"] = line1 + line2 + line3
    # print request_body
    url = "http://localhost:8080/gremlin"
    # pms_encoded = urllib.urlencode(request_body)
    r = requests.post(url, json=request_body)
    # print r.content
    tmp_dict = json.loads(r.content)
    for i in tmp_dict["result"]["data"]:
        key_list = i.keys()
        # print key_list
    degree = []
    candidates = []
    for i in key_list:
        degree.append(int(i))
    degree.sort(reverse=True)
    # print degree
    j = 0
    # 格式奇怪,要自己解析
    if K > len(tmp_dict["result"]["data"][0]):# K不能过大
        K = len(tmp_dict["result"]["data"][0])
    while j < K:
        for item in tmp_dict["result"]["data"][0][str(degree[j])]: # 度相同的节点们
            candidates.append(item["id"])
        j += 1
    return candidates

def execute_Gremlin(script):
    request_body = {
        "bindings": {},
        "language": "gremlin-groovy",
        "aliases": {}
    }
    request_body["gremlin"] = script
    url = "http://localhost:8080/gremlin"
    r = requests.post(url, json=request_body)
    tmp_dict = json.loads(r.content)
    return tmp_dict

def search_attack_event(SYMBOL_LIST, EVENT_SEQUENCE, V, IsCylic):# 一次针对某一个点,匹配一个攻击模式
    print "基于可疑节点进行攻击模式匹配..."
    print V
    search_result = True
    v = V
    start_subsentence = "hugegraph.traversal().V('" + v + "').match(\n"
    match_subsentence = ""
    end_subsentence = ""
    where_subsentence = "" #环路匹配需要
    single_subsentences = []
    i = 0 # i用于取出符号
    for item in EVENT_SEQUENCE:
        if item != "" and i < len(SYMBOL_LIST)-1:
            if i == len(SYMBOL_LIST)-2 and IsCylic:# 环路匹配的最后一节是in边
                single_subsentence = "__.as('" + SYMBOL_LIST[i] + "').in('" + item + "').as('" + SYMBOL_LIST[i+1] + "'),"
            else:
                single_subsentence = "__.as('" + SYMBOL_LIST[i] + "').out('" + item + "').as('" + SYMBOL_LIST[i+1] + "'),"
            single_subsentences.append(single_subsentence)
            i += 1
        else:
            break
    for i in single_subsentences:
        match_subsentence += i
    match_subsentence = match_subsentence[:-1]
    end_subsentence = ").select("
    for symbol in SYMBOL_LIST:
        end_subsentence = end_subsentence + "'" + symbol + "',"
    end_subsentence = end_subsentence[:-1]
    end_subsentence += ")"
    if not IsCylic:
        query_sentence = start_subsentence + match_subsentence + end_subsentence
    else:
        where_subsentence = ").where('" + SYMBOL_LIST[0] + "', eq('" + SYMBOL_LIST[len(SYMBOL_LIST)-1] + "')"
        query_sentence = start_subsentence + match_subsentence + where_subsentence + end_subsentence
    tmp_dict = execute_Gremlin(query_sentence)
    print query_sentence
    if len(tmp_dict["result"]["data"]):
        print "成功!"
    else:
        print "失败!"
        search_result = False
    return search_result
        

def extract_attack_event_by_event_chain(EVENT_CHAIN_PATHS, EVENT_CHAIN_CYCLICPATHS, SUSPICIOUS_NODES):
    print "开始攻击事件匹配..."
    print "匹配无环攻击序列..."
    Malicious_nodes = []
    for V in SUSPICIOUS_NODES:
        IsMalicious = True
        for event in EVENT_CHAIN_PATHS:
            event_sequence = event.split('>')
            # event_sequence中实际事件个数为len(event_sequence)-1,去掉最后的空串
            symbol_list = [] # 符号表中的符号个数应比事件个数多1(点的别名)
            i = 1
            while i <= len(event_sequence):
                symbol_list.append("a" + str((i)))
                i += 1
            if False == search_attack_event(symbol_list, event_sequence, V, False):
                IsMalicious = False
            print symbol_list
        print "匹配环路攻击序列..."
        for event in EVENT_CHAIN_CYCLICPATHS:
            event_sequence = event.split('>')
            symbol_list = []
            i = 1
            while i <= len(event_sequence):
                symbol_list.append("a" + str((i)))
                i += 1
            if False == search_attack_event(symbol_list, event_sequence, V, True):
                IsMalicious = False
            print symbol_list
        if IsMalicious:
            Malicious_nodes.append(V)
    return Malicious_nodes

if __name__ == '__main__':
    # 做的是特征匹配,而不是子图同构匹配,否则漏洞百出
    # 也可以理解为做的是模糊匹配,而不是精确匹配(不需要)
    PATTERN_NUM = 0
    MAX_DISTANCE = 1 # ok
    TIME_WINDOW = 600 # 自己设
    KEY_EVENTS = set() # 取和0点相连的attack_event_n的边的event_label属性, ok
    EVENT_CHAIN_PATHS = []
    EVENT_CHAIN_CYCLICPATHS = []
    SUSPICIOUS_NODES = []
    PATTERNS = 2
    K = 2 # 自己设
    # 从特征图中提取以下要素
    # 从可疑节点出发的匹配规则
    # K值(前K个可疑点),ok
    # 最大距离(限制匹配范围),ok
    # 环的处理(模式匹配/连续out匹配),环仍然要化为匹配规则
    while PATTERN_NUM < PATTERNS:
        KEY_EVENTS.clear() # 集合要清空
        print "开始抽取攻击模式图0的特征信息:"
        # source_node_id = "2:0" # 攻击特征图中的攻击节点
        source_node_id = str(PATTERN_NUM+2) + ":0" # 实际就是相隔2
        MAX_DISTANCE = extract_max_distance(source_node_id)
        print "MAX_DISTANCE = " + str(MAX_DISTANCE)
        print "设置时间窗大小..."
        print "TIME_WINDOW = " + str(TIME_WINDOW)
        print "设置K值..."
        print "K = " + str(K)
        # 匹配规则的格式:
        # 可疑点出发,攻击事件链(思路,从攻击模式图中查找所有的事件链组合,重复也没事,链上每一步可能有不止一个事件(兼备,只要模式匹配能达到这个要求就行))
        # 提取关键事件(用于求边生成子图)
        KEY_EVENTS = extract_key_events(PATTERN_NUM)
        print KEY_EVENTS
        # 提取攻击事件链
        EVENT_CHAIN_PATHS = extract_event_chain_paths(source_node_id, MAX_DISTANCE, PATTERN_NUM)
        print "攻击事件链(无环):"
        print "EVENT_CHAIN_PATHS = "
        print EVENT_CHAIN_PATHS
        EVENT_CHAIN_CYCLICPATHS = extract_event_chain_cyclicpaths(source_node_id, PATTERN_NUM)
        print "攻击事件链(有环):"
        print "EVENT_CHAIN_CYCLICPATHS = "
        print EVENT_CHAIN_CYCLICPATHS
        SUSPICIOUS_NODES = extract_suspicious_nodes_from_datagraph(KEY_EVENTS, K)
        print "可疑节点id:"
        print "SUSPICIOUS_NODES = "
        print SUSPICIOUS_NODES
        MALICIOUS_NODES = extract_attack_event_by_event_chain(EVENT_CHAIN_PATHS, EVENT_CHAIN_CYCLICPATHS, SUSPICIOUS_NODES)
        print "恶意节点id:"
        print "MALICIOUS_NODES = "
        print MALICIOUS_NODES
        PATTERN_NUM += 1

