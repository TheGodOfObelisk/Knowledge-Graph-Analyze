graph.schema().propertyKey("ip").asText().ifNotExist().create()
graph.schema().propertyKey("frequency").asInt().ifNotExist().create()
graph.schema().propertyKey("vertex_type").asText().ifNotExist().create()
graph.schema().propertyKey("edge_type").asText().ifNotExist().create()
graph.schema().propertyKey("time").asText().ifNotExist().create()

host = graph.schema().vertexLabel("host").properties("ip", "time", "vertex_type").primaryKeys("ip").ifNotExist().create()
server = graph.schema().vertexLabel("server").properties("ip", "time", "vertex_type").primaryKeys("ip").ifNotExist().create()

ping = graph.schema().edgeLabel("ping").sourceLabel("host").targetLabel("server").properties("time", "edge_type").ifNotExist().create()
reply = graph.schema().edgeLabel("reply").sourceLabel("server").targetLabel("host").properties("time", "edge_type").ifNotExist().create()

thinkpad = graph.addVertex(T.label, "host", "ip", "192.168.1.157", "time", "2019-11-07-11:25:16", "vertex_type", "PC")
Galaxy_server = graph.addVertex(T.label, "server", "ip", "202.55.12.142", "time", "2019-11-07-11:28:35", "vertex_type", "WorkStation")
thinkpad.addEdge("ping", Galaxy_server, "edge_type", "ping_echo_request", "time", "2019-11-07-11:32:21")