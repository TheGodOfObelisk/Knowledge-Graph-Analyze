# -*- coding: UTF-8 -*- 
import requests, json
from urlparse import urlparse

def client_post_formurlencodeddata_requests(request_url,requestJSONdata):
    #功能说明：发送以form表单数据格式（它要求数据名称（name）和数据值（value）之间以等号相连，与另一组name/value值之间用&相连。例如：parameter1=12345&parameter2=23456。）请求到远程服务器，并获取请求响应报文。该请求消息头要求为：{"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}。
    #输入参数说明：接收请求的URL;请求报文数据，格式为name1=value1&name2=value2
    #输出参数：请求响应报文      
 
    requestJSONdata=str(requestJSONdata).replace("+", "%2B")
    requestdata=requestJSONdata.encode("utf-8")
    head = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", 'Connection': 'close'}
     
    print '客户端请求JSON报文数据为（客户端 --> 服务端）:\n',requestdata
     
    #客户端发送请求报文到服务端
    r = requests.post(request_url,data=requestdata,headers=head)
     
    #客户端获取服务端的响应报文数据
    responsedata = r.text
    print '服务端的响应报文为（客户端 <--服务端）: ',responsedata
    print "get the status: ",r.status_code
        
    #返回请求响应报文
    return responsedata


# text = ""
# with open("test.json", "r") as f:
#     text = f.read()
# print text

# 定义请求header
HEADERS = {'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8', 'Key': '332213fa4a9d4288b5668ddd9'}

url = "http://localhost:8080/graphs/hugegraph/graph/edges"
# data_f = open('test.json', 'r')
# data = json.load(data_f)
data = {
    "label": "icmp_echo_ping",
    "outV": "1:202.77.162.213",
    "inV": "1:172.16.115.1",
    "outVLabel": "entity",
    "inVLabel": "entity",
    "properties": {
        "edge_type": "basic_event", 
        "ts": "952440696.029745", 
        "time": "2000-03-07-22:51:36", 
        "frequency": 1, 
        "src_ip": "202.77.162.213", 
        "src_p": "8", 
        "dst_ip": "172.16.115.1", 
        "dst_p": "0"
    }
}
print type(data)
data = json.dumps(data)

r = requests.post(url, data)
print r.text

# requestbody = """'{
#     "label": "icmp_echo_ping",
#     "outV": "1:202.77.162.213",
#     "inV": "1:172.16.115.1",
#     "outVLabel": "entity",
#     "inVLabel": "entity",
#     "properties": {
#         "edge_type": "basic_event", 
#         "ts": "952440696.029745", 
#         "time": "2000-03-07-22:51:36", 
#         "frequency": 1, 
#         "src_ip": "202.77.162.213", 
#         "src_p": "8", 
#         "dst_ip": "172.16.115.1", 
#         "dst_p": "0"
#     }
# }'"""

requestbody = """'{
    "label": "entity",
    "properties": {
        "ip": "202.77.162.213",
        "ips": "2000-03-07-22:51:36|202.77.162.213",
        "ts": "952440722.006110",
        "vertex_type": "asset",
        "status": "unknown"
    }
}'"""
t1 = "202.77.162.213"
t2 = "952440722.006110"
t3 = "2000-03-07-22:51:36|202.77.162.213"
requestbody = """ '{
        "label": "entity",
        "properties": {
        "ip": "%s",
        "ips": "%s",
        "ts": "%s",
        "vertex_type": "asset",
        "status": "unknown"
    }
}' """%(t1, t2, t3)

cmd =  """curl -X POST -H "Content-Type:application/json" http://localhost:8080/graphs/hugegraph/graph/vertices -d"""
cmd = cmd + requestbody
print cmd
# client_post_formurlencodeddata_requests(url, data)
# content = requests.post(url=url, headers=HEADERS, data=data).text
# content = json.loads(content)
# print content