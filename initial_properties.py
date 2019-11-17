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
edgeTypes = ["icmp_echo_ping", "icmp_echo_reply", "icmp_unreachable", "rpc_reply", "rpc_call", "portmap", 
 "new_connection_contents", "connection_SYN_packet", "tcp_packet", "connection_established",
 "connection_first_ack", "connection_eof", "connection_finished", "connection_pending", "login_output_line",
 "login_input_line", "login_confused", "login_confused_text", "login_success", "rsh_request",
 "rsh_reply", "connection_attempt", "login_terminal", "connection_half_finished", "login_display",
 "http_event", "http_stats", "http_end_entity", "http_message_done", "heep_content_type",
 "http_all_headers", "http_reply", "http_header", "http_begin_entity", "http_entity_data"]

edge_type_value = []

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
    # cmd = """curl -X POST -H "Content-Type:application/json" http://localhost:8080/graphs/hugegraph/schema/indexlabels -d"""
    # requestbody = """'{
    #         "name": "entityByip",
    #         "base_type": "VERTEX_LABEL",
    #         "base_value": "entity",
    #         "index_type": "SECONDARY",
    #         "fields": [
    #             "vertex_type"
    #         ]
    #     }'"""
    # cmd = cmd + requestbody
    n = 1
    for i in edgeTypes:
        dict_item = {}
        dict_item[i] = n
        n += 1
        edge_type_value.append(dict_item)
    print edge_type_value

    # cmd = """GET http://127.0.0.1:8080/graphs/hugegraph/graph/edges?vertex_id="1:202.77.162.213"&direction=OUT&label=icmp_echo_ping&properties={}"""

    # cmd = """curl http://localhost:8080/graphs/hugegraph/graph/edges/'S1:202.77.162.213>1>>S1:172.16.113.95'"""

    # cmd = """curl -X PUT http://localhost:8080/graphs/hugegraph/graph/edges/'S1:202.77.162.213>1>>S1:172.16.112.94'?action=append -d """
    # requestbody = """'{"properties":{"frequency": 2}}'"""
    # cmd = cmd + requestbody
    # print cmd
    # sub = subprocess.Popen(cmd, shell = True, stdout = subprocess.PIPE)
    # str1 = sub.stdout.read()
    # sub.communicate()
    # str1 = str1.decode()
    # print str1


    # requestbody = """'{
    #         "name": "entityByip",
    #         "base_type": "VERTEX_LABEL",
    #         "base_value": "entity",
    #         "index_type": "SECONDARY",
    #         "fields": [
    #             "ip"
    #         ]
    #     }'"""
    # cmd = """curl -X POST -H "Content-Type:application/json" http://localhost:8080/graphs/hugegraph/schema/indexlabels -d"""


    requestbody = """'{"properties":{"frequency": 2}}'"""
    cmd="""curl -X PUT -H "Content-Type:application/json" http://localhost:8080/graphs/hugegraph/graph/edges/"S1:202.77.162.213>1>>S1:172.16.113.95"?action=append -d"""
    cmd = cmd + requestbody
    print cmd
