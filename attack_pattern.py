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
    # requestbody = """'{
    #     "name": "attack_event_0",
    #     "source_label": "attack_pattern_0",
    #     "target_label": "attack_pattern_0",
    #     "frequency": "SINGLE",
    #     "properties": [
    #         "pattern_edge_id",
    #         "event_label"
    #     ],
    #     "sort_keys": [],
    #     "nullable_keys": [],
    #     "enable_label_index": true
    # }'"""
    # cmd = """curl -X POST -H "Content-Type:application/json" http://localhost:8080/graphs/hugegraph/schema/edgelabels -d"""
    # cmd += requestbody
    # print cmd

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
        print res[0]
        print res[1]


