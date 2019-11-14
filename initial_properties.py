# -*- coding: UTF-8 -*-
import os
import subprocess
def extractText(text):
    res = text.split(' ')
    return res
n = 0
vertexs = []
events = []
propertyKeys_txt = ["ip", "ts", "vertex_type", "edge_type", "time", "ips", "status", "src_ip", "src_p", "dst_ip", "dst_p", "description"]
propertyKeys_int = ["frequency"]
vertexTypes = ["entity"]
edgeTypes = ["icmp_echo_ping", "icmp_echo_reply", "icmp_unreachable", "rpc_reply", "rpc_call", "portmap"]

if __name__ == '__main__':
    # cmd = "cat host-summary.log | bro-cut"
    with open("gremlin_scripts_0", "w") as f:
        for item in propertyKeys_txt:
            line = """graph.schema().propertyKey("{key}").asText().ifNotExist().create()\n""".format(key = item)
            f.write(line)
        for item in propertyKeys_int:
            line = """graph.schema().propertyKey("{key}").asInt().ifNotExist().create()\n""".format(key = item)
            f.write(line)
        for item in vertexTypes:# 不同类型顶点应拥有不同的属性,待完善
            line = """entity = graph.schema().vertexLabel("{label}").properties("ip", "ips", "ts", "vertex_type", "status").primaryKeys("ip").ifNotExist().create()\n""".format(label = item)
            f.write(line)
        for item in edgeTypes:# 不同类型边应拥有不同的属性,待完善
            line = """{edge_variable} = graph.schema().edgeLabel("{edge_variable}").sourceLabel("entity").targetLabel("entity").properties("edge_type", "ts", "time", "frequency", "src_ip", "src_p", "dst_ip", "dst_p", "description").ifNotExist().create()\n""".format(edge_variable = item)
            f.write(line)
        f.close()