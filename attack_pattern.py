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

if __name__ == '__main__':
    for key in property_keys:
        requestbody = """'{
            "name": "%s",
            "data_type": "TEXT",
            "cardinality": "SINGLE"
        }'"""%key
        cmd = """curl -X POST -H "Content-Type:application/json" http://localhost:8080/graphs/hugegraph/schema/propertykeys -d"""
        cmd += requestbody
        print cmd
    # requestbody = """'{
    #     "name": "attack_pattern_0",
    #     "id_strategy": "DEFAULT",
    #     "properties": [
    #         "name",
    #         "age"
    #     ],
    #     "primary_keys": [
    #         "name"
    #     ],
    #     "nullable_keys": [],
    #     "enable_label_index": true
    # }'"""