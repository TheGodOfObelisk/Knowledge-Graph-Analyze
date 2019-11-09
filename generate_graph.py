# -*- coding: UTF-8 -*-
# author: wangyixuan 
# 与hugegraph-server交互,根据LLS_DDOS_1.0内容创建网络事件图谱
# 要求:
# 1. 属性图结构
# 2. 采用Gremlin图计算语言
# 3. 自动化处理
# import subprocess
# cmd = "cat host-summary.log | bro-cut"
# sub = subprocess.Popen(cmd, shell = True, stdout = subprocess.PIPE)
# str1 = sub.stdout.read()
# sub.communicate()
# print str1
# for i in iter(sub.stdout.readline):
#     print i

import os
import subprocess
def extractText(text):
    res = text.split(' ')
    return res
n = 0
vertexs = []
events = []
propertyKeys_txt = ["ip", "ts", "vertex_type", "edge_type", "time", "ips", "status", "src_ip", "src_p", "dst_ip",	"dst_p"]
propertyKeys_int = ["frequency"]
vertexTypes = ["entity"]
edgeTypes = ["icmp_echo_ping", "icmp_echo_reply"]

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
            line = """{edge_variable} = graph.schema().edgeLabel("{edge_variable}").sourceLabel("entity").targetLabel("entity").properties("edge_type", "ts", "time", "frequency", "src_ip", "src_p", "dst_ip", "dst_p").ifNotExist().create()\n""".format(edge_variable = item)
            f.write(line)
        f.close()
    cmd = "awk '/^[^#]/ {print $1, $2, $3}' host-summary.log"
    r = os.popen(cmd)
    text = r.readline()
    print text
    while text != "":
        # print type(text)
        text = text.strip('\n')
        res = extractText(text)
        if len(res) != 0 and len(res) != 1:
            res.append("Vertex" + str(n))
            print res
            vertexs.append(res)
        text = r.readline()
        n += 1
    with open("gremlin_scripts_1", "w") as f:
        for item in vertexs:
            # 0: ts, 1: ip, 2: ips, 3: variable name
            line = """{vertex_variable} = graph.addVertex(T.label, "entity", "ip", "{t_ip}", "ips", "{t_ips}", "ts", "{t_ts}", "vertex_type", "asset", "status", "unknown")\n""".format(vertex_variable = item[3], t_ips = item[2], t_ip = item[1], t_ts = item[0])
            print line
            f.write(line)
            requestbody = """'{
                "label": "entity",
                "properties": {
                    "ip": "%s",
                    "ips": "%s",
                    "ts": "%s",
                    "vertex_type": "asset",
                    "status": "unknown"
                }
            }'"""%(item[1], item[2], item[0])
            cmd = """curl -X POST -H "Content-Type:application/json" http://localhost:8080/graphs/hugegraph/graph/vertices -d"""
            cmd = cmd + requestbody
            print cmd
            sub = subprocess.Popen(cmd, shell = True, stdout = subprocess.PIPE)
            str1 = sub.stdout.read()
            sub.communicate()
            str1 = str1.decode()
            print str1
        f.close()
    print len(vertexs)
    print n
    cmd = "awk '/^[^#]/ {print $1, $2, $3, $4, $5, $6, $7}' network_events.log"
    r = os.popen(cmd)
    text = r.readline()
    while text != "":
        text = text.strip('\n')
        res = extractText(text)
        if len(res) != 0 and len(res) != 1:
            # 边似乎不用边变量
            events.append(res)
        text = r.readline()
    # v_src,v_dst为顶点变量名,用于连线
    v_src = ""
    v_dst = ""
    with open("gremlin_scripts_2", "a") as f:
        for item in events:
            # 先确定是哪两个点相连
            # 0: ts, 1: real_time, 2: event_type, 3: src_ip, 4: src_p, 5: dst_ip, 6: dst_p
            src_ip = item[3]
            dst_ip = item[5]
            # print src_ip
            # print dst_ip
            for v in vertexs:
                if v[1] == src_ip:
                    # print "!!!"
                    v_src = v[3]
                    continue
                if v[1] == dst_ip:
                    # print "!!!!"
                    v_dst = v[3]
                    continue
            if v_src != "" and v_dst != "":
                edge_label = ""
                if item[2] == "HOST_INFO::ICMP_ECHO_REQUEST":
                    line = """{t_v_src}.addEdge("icmp_echo_ping", {t_v_dst}, "edge_type", "basic_event", "ts", "{t_ts}", "time", "{t_time}", "frequency", 1, "src_ip", "{t_src_ip}", "src_p", "{t_src_p}", "dst_ip", "{t_dst_ip}", "dst_p", "{t_dst_p}")\n""".format(
                        t_v_src = v_src, t_v_dst = v_dst, t_ts = item[0], t_time = item[1], t_src_ip = item[3], t_src_p = item[4], t_dst_ip = item[5], t_dst_p = item[6]
                    )
                    f.write(line)
                    edge_label = "icmp_echo_ping"
                elif item[2] == "HOST_INFO::ICMP_ECHO_REPLY":
                    line = """{t_v_src}.addEdge("icmp_echo_reply", {t_v_dst}, "edge_type", "basic_event", "ts", "{t_ts}", "time", "{t_time}", "frequency", 1, "src_ip", "{t_src_ip}", "src_p", "{t_src_p}", "dst_ip", "{t_dst_ip}", "dst_p", "{t_dst_p}")\n""".format(
                        t_v_src = v_src, t_v_dst = v_dst, t_ts = item[0], t_time = item[1], t_src_ip = item[3], t_src_p = item[4], t_dst_ip = item[5], t_dst_p = item[6]
                    )
                    f.write(line)
                    edge_label = "icmp_echo_reply"
                t_src_ip = item[3]
                t_dst_ip = item[5]
                t_ts = item[0]
                t_time = item[1]
                t_src_p = item[4]
                t_dst_p = item[6]
                requestbody = """'{
                    "label": "%s",
                    "outV": "1:%s",
                    "inV": "1:%s",
                    "outVLabel": "entity",
                    "inVLabel": "entity",
                    "properties": {
                        "edge_type": "basic_event", 
                        "ts": "%s", 
                        "time": "%s", 
                        "frequency": 1, 
                        "src_ip": "%s", 
                        "src_p": "%s", 
                        "dst_ip": "%s", 
                        "dst_p": "%s"
                    }
                }'"""%(edge_label, t_src_ip, t_dst_ip, t_ts, t_time, t_src_ip, t_src_p, t_dst_ip, t_dst_p)
                cmd =  """curl -X POST -H "Content-Type:application/json" http://localhost:8080/graphs/hugegraph/graph/edges -d"""
                cmd = cmd + requestbody
                sub = subprocess.Popen(cmd, shell = True, stdout = subprocess.PIPE)
                str1 = sub.stdout.read()
                sub.communicate()
                str1 = str1.decode()
                print str1
            else:
                print "没有找到合适的两个点"
        f.close()
    # print vertexs
    r.close()
