# -*- coding: UTF-8 -*-
# author: wangyixuan 
# 网络攻击特征事件图谱生成,攻击模式应当自动生成,并能自动增长
# 考虑使用不同的顶点标签来表示不同的攻击模式,攻击模式的点边属性该怎么设置?
import os
import subprocess

# 创建顺序
# 1. 属性类型
# 2. 攻击模式点类型
# 3. 攻击模式边类型
# 4. 攻击模式数据(定制)

property_keys = ["event_label", "pattern_node_id", "pattern_edge_id"]
edges = []

def extractText(text):
    res = text.split(' ')
    return res

def addNode(v, name):
    requestbody = """'{
        "label": "%s",
        "properties": {
            "pattern_node_id": %s
        }
    }'"""%(name, v)
    # 实际上是整数
    cmd = """curl -X POST -H "Content-Type:application/json" http://localhost:8080/graphs/hugegraph/graph/vertices -d"""
    cmd = cmd + requestbody
    print cmd
    sub = subprocess.Popen(cmd, shell = True, stdout = subprocess.PIPE)
    str1 = sub.stdout.read()
    sub.communicate()
    str1 = str1.decode()
    print str1
    return

def addEdge(v1, v2, event_label, edge_num, event_seq):
    # 必须知道两点的id,很糟
    edge_name = "attack_event_" + event_seq
    node_name = "attack_pattern_" + event_seq
    n = int(event_seq) + 4 # 1是entity,2开始才是攻击模式   有点问题,需要处理冒号前的序号
    requestbody = """'{
        "label": "%s",
        "outV": "%d:%s",
        "inV": "%d:%s",
        "outVLabel": "%s",
        "inVLabel": "%s",
        "properties": {
            "pattern_edge_id": %s,
            "event_label": "%s"
        }
    }
    '"""%(edge_name, n, v1, n, v2, node_name, node_name, edge_num, event_label)
    cmd =  """curl -X POST -H "Content-Type:application/json" http://localhost:8080/graphs/hugegraph/graph/edges -d"""
    cmd = cmd + requestbody
    print cmd
    sub = subprocess.Popen(cmd, shell = True, stdout = subprocess.PIPE)
    str1 = sub.stdout.read()
    sub.communicate()
    str1 = str1.decode()
    print str1
    return

def execute_command(cmd):
    sub = subprocess.Popen(cmd, shell = True, stdout = subprocess.PIPE)
    str1 = sub.stdout.read()
    sub.communicate()
    str1 = str1.decode()
    # print str1
    return str1

# 攻击特征子图发现,通过gremlin提供的subgraph功能,先作一步过滤
# 过滤方法(基于边标签)
# 边标签可以取自攻击特征子图的边属性
# gremlin提供的子图中的所有节点,都可能参与/被波及
# 然后关注子图的点出度,出度高的点,可疑度高

if __name__ == '__main__':
    # for key in property_keys:
    #     requestbody = """'{
    #         "name": "%s",
    #         "data_type": "TEXT",
    #         "cardinality": "SINGLE"
    #     }'"""%key
    #     cmd = """curl -X POST -H "Content-Type:application/json" http://localhost:8080/graphs/hugegraph/schema/propertykeys -d"""
    #     cmd += requestbody
    #     print cmd

    # 攻击模式点标签
    # requestbody = """'{
    #     "name": "attack_pattern_0",
    #     "id_strategy": "DEFAULT",
    #     "properties": [
    #         "pattern_node_id"
    #     ],
    #     "primary_keys": [
    #         "pattern_node_id"
    #     ],
    #     "nullable_keys": [],
    #     "enable_label_index": true
    # }'"""
    # cmd = """curl -X POST -H "Content-Type:application/json" http://localhost:8080/graphs/hugegraph/schema/vertexlabels -d"""
    # cmd += requestbody
    # print cmd

    # 攻击模式边标签
    # 没办法了,要标明源节点和目的节点的标签,标签的爆炸式增长
    max_squence = 3
    i = 0
    while i <= max_squence:
        requestbody = """'{
            "name": "attack_pattern_%d",
            "id_strategy": "DEFAULT",
            "properties": [
                "pattern_node_id"
            ],
            "primary_keys": [
                "pattern_node_id"
            ],
            "nullable_keys": [],
            "enable_label_index": true
        }'"""%(i)
        cmd = """curl -X POST -H "Content-Type:application/json" http://localhost:8080/graphs/hugegraph/schema/vertexlabels -d"""
        cmd += requestbody
        print execute_command(cmd)
        requestbody = """'{
            "name": "attack_event_%d",
            "source_label": "attack_pattern_%d",
            "target_label": "attack_pattern_%d",
            "frequency": "SINGLE",
            "properties": [
                "pattern_edge_id",
                "event_label"
            ],
            "sort_keys": [],
            "nullable_keys": [],
            "enable_label_index": true
        }'"""%(i, i, i)
        cmd = """curl -X POST -H "Content-Type:application/json" http://localhost:8080/graphs/hugegraph/schema/edgelabels -d"""
        cmd += requestbody
        print execute_command(cmd)
        i += 1
    cmd = "awk '/^[^#]/ {print $1, $2, $3, $4}' attack_pattern_event.log"
    r = os.popen(cmd)
    text = r.readline()
    while text != "":
        text = text.strip('\n')
        res = extractText(text)
        if len(res) != 0 and len(res) != 1:
            # 边似乎不用边变量
            edges.append(res)
        text = r.readline()
    print edges
    for item in edges:
        # 0: 节点标签, 1: 边序号, 2: 边事件描述, 3: 连接关系
        res = item[3].split('>')
        print res
        # 先建点,再建边
        v1 = res[0]
        v2 = res[1]
        addNode(v1, item[0])
        addNode(v2, item[0])
        event_label = item[2]
        edge_num = item[1]
        addEdge(v1, v2, event_label, edge_num, item[0][-1])
        
    # gremline_for_pattern_0 = """subGraph = g.E().hasLabel('icmp_echo_ping').subgraph('subGraph').cap('subGraph').next()
    #                         sg = subGraph.traversal()
    #                         sg.E()"""
    # 按边标签过滤,抽取子图

