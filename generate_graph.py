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

# 动态构建图谱需要考虑的问题
# 按照顶点id来取顶点的方法不好
# 不同类型的顶点或者边有着不同的属性,request_data需要重新考量

# 去除写gremlin文件的内容,仅保留gremlin_script0

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
edgeTypes = 
["icmp_echo_ping", "icmp_echo_reply", "icmp_unreachable", "rpc_reply", "rpc_call", "portmap", 
 "new_connection_contents", "connection-SYN-packet", "tcp_packet", "connection_established",
 "connection_first_ack", "connection_eof", "connection_finished", "connection_pending", "login_output_line",
 "login_input_line", "login_confused", "login_confused_text", "login_success", "rsh_request",
 "rsh_reply", "connection_attempt", "login_terminal", "connection_half_finished", "login_display"]

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
    for item in vertexs:
        # 0: ts, 1: ip, 2: ips, 3: variable name
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
    print len(vertexs)
    print n
    cmd = "awk '/^[^#]/ {print $1, $2, $3, $4, $5, $6, $7, $8}' network_events.log"
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
    for item in events:
        # 先确定是哪两个点相连
        # 0: ts, 1: real_time, 2: event_type, 3: src_ip, 4: src_p, 5: dst_ip, 6: dst_p, 7: description
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
                # line = """{t_v_src}.addEdge("icmp_echo_ping", {t_v_dst}, "edge_type", "basic_event", "ts", "{t_ts}", "time", "{t_time}", "frequency", 1, "src_ip", "{t_src_ip}", "src_p", "{t_src_p}", "dst_ip", "{t_dst_ip}", "dst_p", "{t_dst_p}")\n""".format(
                #     t_v_src = v_src, t_v_dst = v_dst, t_ts = item[0], t_time = item[1], t_src_ip = item[3], t_src_p = item[4], t_dst_ip = item[5], t_dst_p = item[6]
                # )
                # f.write(line)
                edge_label = "icmp_echo_ping"
            elif item[2] == "HOST_INFO::ICMP_ECHO_REPLY":
                # line = """{t_v_src}.addEdge("icmp_echo_reply", {t_v_dst}, "edge_type", "basic_event", "ts", "{t_ts}", "time", "{t_time}", "frequency", 1, "src_ip", "{t_src_ip}", "src_p", "{t_src_p}", "dst_ip", "{t_dst_ip}", "dst_p", "{t_dst_p}")\n""".format(
                #     t_v_src = v_src, t_v_dst = v_dst, t_ts = item[0], t_time = item[1], t_src_ip = item[3], t_src_p = item[4], t_dst_ip = item[5], t_dst_p = item[6]
                # )
                # f.write(line)
                edge_label = "icmp_echo_reply"
            elif item[2] == "HOST_INFO::ICMP_UNREACHABLE":
                # line = """{t_v_src}.addEdge("icmp_unreachable", {t_v_dst}, "edge_type", "basic_event", "ts", "{t_ts}", "time", "{t_time}", "frequency", 1, "src_ip", "{t_src_ip}", "src_p", "{t_src_p}", "dst_ip", "{t_dst_ip}", "dst_p", "{t_dst_p}")\n""".format(
                #     t_v_src = v_src, t_v_dst = v_dst, t_ts = item[0], t_time = item[1], t_src_ip = item[3], t_src_p = item[4], t_dst_ip = item[5], t_dst_p = item[6]
                # )
                # f.write(line)
                edge_label = "icmp_unreachable"
            elif item[2] == "HOST_INFO::RPC_REPLY":
                edge_label = "rpc_reply"
            elif item[2] == "HOST_INFO::RPC_CALL":
                edge_label = "rpc_call"
            elif item[2] == "HOST_INFO::PORTMAP":
                edge_label = "portmap"
            elif item[2] == "HOST_INFO::NEW_CONNECTION_CONTENTS":
                edge_label = "new_connection_contents"
            elif item[2] == "HOST_INFO::CONNECTION-SYN-PACKET":
                edge_label = "connection-SYN-packet"
            elif item[2] == "HOST_INFO::TCP_PACKET":
                edge_label = "tcp_packet"
            elif item[2] == "HOST_INFO::CONNECTION-ESTABLISHED":
                edge_label = "connection-established"
            elif item[2] == "HOST_INFO::CONNECTION_FIRST_ACK":
                edge_label = "connection_first_ack"
            elif item[2] == "HOST_INFO::CONNECTION_EOF":
                edge_label = "connection_eof"
            elif item[2] == "HOST_INFO::CONNECTION_FINISHED":
                edge_label = "connection_finished"
            elif item[2] == "HOST_INFO::CONNECTION_PENDING":
                edge_label = "connection_pending"
            elif item[2] == "HOST_INFO::LOGIN_OUTPUT_LINE":
                edge_label = "login_output_line"
            elif item[2] == "HOST_INFO::LOGIN_INPUT_LINE":
                edge_label = "login_input_line"
            elif item[2] == "HOST_INFO::LOGIN_CONFUSED":
                edge_label = "login_confused"
            elif item[2] == "HOST_INFO::LOGIN_CONFUSED_TEXT":
                edge_label = "login_confused_text"
            elif item[2] == "HOST_INFO::LOGIN_SUCCESS":
                edge_label = "login_success"
            elif item[2] == "HOST_INFO::RSH_REQUEST":
                edge_label = "rsh_request"
            elif item[2] == "HOST_INFO::RSH_REPLY":
                edge_label = "rsh_reply"
            elif item[2] == "HOST_INFO::CONNECTION_ATTEMPT":
                edge_label = "connection_attempt"
            elif item[2] == "HOST_INFO::LOGIN_TERMINAL":
                item[2] = "login_terminal"
            elif item[2] == "HOST_INFO::CONNECTION_HALF_FINISHED":
                item[2] = "connection_half_finished"
            elif item[2] == "HOST_INFO::LOGIN_DISPLAY":
                item[2] = "login_display"
            t_src_ip = item[3]
            t_dst_ip = item[5]
            t_ts = item[0]
            t_time = item[1]
            t_src_p = item[4]
            t_dst_p = item[6]
            t_description = item[7]
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
                    "dst_p": "%s",
                    "description": "%s"
                }
            }'"""%(edge_label, t_src_ip, t_dst_ip, t_ts, t_time, t_src_ip, t_src_p, t_dst_ip, t_dst_p, t_description)
            cmd =  """curl -X POST -H "Content-Type:application/json" http://localhost:8080/graphs/hugegraph/graph/edges -d"""
            cmd = cmd + requestbody
            print cmd
            sub = subprocess.Popen(cmd, shell = True, stdout = subprocess.PIPE)
            str1 = sub.stdout.read()
            sub.communicate()
            str1 = str1.decode()
            print str1
        else:
            print "没有找到合适的两个点"
    # f.close()
    # print vertexs
    r.close()
