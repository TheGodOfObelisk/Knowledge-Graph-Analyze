#!/usr/bin/env python
# -*- coding: utf-8 -*-


# ok
# import json
# import requests

# url = "http://localhost:8080/graphs/hugegraph/graph/edges/S1:202.77.162.213>1>>S1:172.16.113.95"
# response = requests.get(url)
# print response.status_code
# print type(response.text)
# text = response.text
# str1 = text.encode('gbk')
# print type(str1)
# jdata = json.loads(str1)
# print jdata["properties"]["frequency"]
# print type(jdata)
# ok

# import urllib2
# import json
 
# def putMesParent():
#   try:
#     # 将参数存储为键值对形式
#     value = {"properties":{"frequency": 2}}
#     # json封装
#     jdata = json.dumps(value,indent=4)
#     print jdata
#     # 与服务器交互，进行put请求
#     url = """http://localhost:8080/graphs/hugegraph/graph/edges/'S1:202.77.162.213>1>>S1:172.16.113.95'?action=append"""
#     request = urllib2.Request(url, jdata)
#     # 这行很重要,put一定要用这个
#     request.add_header("Content-Type","application/json; charset=utf-8")
#     # 设置返回值为put方式
#     request.get_method = lambda:"PUT"
#     # 得到返回结果
#     result = urllib2.urlopen(request)
#     # 返回结果
#     return result
#   except Exception,e:
#     print Exception,":",e
 
# # 访问方法，并返回结果
# print putMesParent()

#!/usr/bin/env python
# -*- coding:utf-8 -*-
# File: http_put.py

# import urllib2
# import json

# def http_put():
#     url="""http://localhost:8080/graphs/hugegraph/graph/edges/\"S1:202.77.162.213>1>>S1:172.16.113.95\"?action=append"""
#     values={"properties":{"frequency": 2}}

#     jdata = json.dumps(values)                  # 对数据进行JSON格式化编码
#     request = urllib2.Request(url, jdata)
#     request.add_header('Content-Type', 'application/json')
#     request.get_method = lambda:'PUT'           # 设置HTTP的访问方式
#     request = urllib2.urlopen(request)
#     return request.read()

# resp = http_put()
# print resp