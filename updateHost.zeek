# author: wangyixuan
# It aims at getting hosts'
# USERNAME,    0      pay attention to NTLM PLZ
# HOSTNAME,      1
# MAC ADDRESS,  1
# OPERATING SYSTEM,     1
# IP ADDRESS    1

# How to sort ips?
# Type          (indicates devicetype, etc desktop, laptop, tablet)
# Applications  (Why do we need it? Should we guess during which period such applications are running?)
# Protocols     (so many protocols, how to handle them? It exists between two hosts.)

# Maintain the information of hosts all the time and output it to log file regularly

# completed two functions named update_hostlist and update_single_host

# event new_connection: collect various protocols which are indicated by connections
# event protocol_confirmation: this event is emitted when bro confirms that this protocol is actually running here
# problem to solve: whether the protocols comes is a new protocol? Using !in is not appropriate.

# adjust the format of protocols   etc: http:33,dns:14
# data to log cannot be a table

# how to invoke a event in a specific interval
# refer to test1.bro and define an event by ourself
# this user-defined event can complish the task of logging hostlist every n seconds
# outside dataprocesser can read the log every n seconds as well

# convert ts to the form of "YYYY:MM:DD-HH:MM:SS", which is easier to understand
# in "ips": mark the timestamp of each ip
# in "protocols": mark the number that indicate how many time this protocol has beem confirmed
# the value of n is dynamic
# there are some problems in updating ips
# 1. segment fault
# 2. redundant ip in "ips" field
# 3, three records missing ips(uninitialized)
# 4. the way to check a ip already exist? etc: 192.168.1.5, 192.168.1.50 substring is not reliable
# @load /home/lw/myKGA/signature_test.bro
@load /usr/local/zeek/share/zeek/policy/frameworks/dpd/detect-protocols.zeek
@load /usr/local/zeek/share/zeek/policy/frameworks/dpd/packet-segment-logging.zeek

module HOST_INFO;

const pm_ports = { 111/udp, 111/tcp };
const telnet_ports = { 23/tcp };
const rsh_ports = { 514/tcp };
redef likely_server_ports += {pm_ports, telnet_ports, rsh_ports};

redef ProtocolDetector::valids += {[Analyzer::ANALYZER_PORTMAPPER, 0.0.0.0, 111/udp] = ProtocolDetector::BOTH};

# declarations of my own events
global portmapper_call: function(c: connection);

global event_counts: int = 0;

const analyzer_tags: set[Analyzer::Tag] = {
    Analyzer::ANALYZER_AYIYA,
    Analyzer::ANALYZER_BITTORRENT,
    Analyzer::ANALYZER_BITTORRENTTRACKER,
    Analyzer::ANALYZER_CONNSIZE,
    Analyzer::ANALYZER_DCE_RPC,
    Analyzer::ANALYZER_DHCP,
    Analyzer::ANALYZER_DNP3_TCP,
    Analyzer::ANALYZER_DNP3_UDP,
    Analyzer::ANALYZER_CONTENTS_DNS,
    Analyzer::ANALYZER_DNS,
    Analyzer::ANALYZER_FTP_DATA,
    Analyzer::ANALYZER_IRC_DATA,
    Analyzer::ANALYZER_FINGER,
    Analyzer::ANALYZER_FTP,
    Analyzer::ANALYZER_FTP_ADAT,
    Analyzer::ANALYZER_GNUTELLA,
    Analyzer::ANALYZER_GSSAPI,
    Analyzer::ANALYZER_GTPV1,
    Analyzer::ANALYZER_HTTP,
    Analyzer::ANALYZER_ICMP,
    Analyzer::ANALYZER_IDENT,
    Analyzer::ANALYZER_IMAP,
    Analyzer::ANALYZER_IRC,
    Analyzer::ANALYZER_KRB,
    Analyzer::ANALYZER_KRB_TCP,
    Analyzer::ANALYZER_CONTENTS_RLOGIN,
    Analyzer::ANALYZER_CONTENTS_RSH,
    Analyzer::ANALYZER_LOGIN,
    Analyzer::ANALYZER_NVT,
    Analyzer::ANALYZER_RLOGIN,
    Analyzer::ANALYZER_RSH,
    Analyzer::ANALYZER_TELNET,
    Analyzer::ANALYZER_MODBUS,
    Analyzer::ANALYZER_MQTT,
    Analyzer::ANALYZER_MYSQL,
    Analyzer::ANALYZER_CONTENTS_NCP,
    Analyzer::ANALYZER_NCP,
    Analyzer::ANALYZER_CONTENTS_NETBIOSSSN,
    Analyzer::ANALYZER_NETBIOSSSN,
    Analyzer::ANALYZER_NTLM,
    Analyzer::ANALYZER_NTP,
    Analyzer::ANALYZER_PIA_TCP,
    Analyzer::ANALYZER_PIA_UDP,
    Analyzer::ANALYZER_POP3,
    Analyzer::ANALYZER_RADIUS,
    Analyzer::ANALYZER_RDP,
    Analyzer::ANALYZER_RFB,
    Analyzer::ANALYZER_CONTENTS_NFS,
    Analyzer::ANALYZER_CONTENTS_RPC,
    Analyzer::ANALYZER_MOUNT,
    Analyzer::ANALYZER_NFS,
    Analyzer::ANALYZER_PORTMAPPER,
    Analyzer::ANALYZER_SIP,
    Analyzer::ANALYZER_CONTENTS_SMB,
    Analyzer::ANALYZER_SMB,
    Analyzer::ANALYZER_SMTP,
    Analyzer::ANALYZER_SNMP,
    Analyzer::ANALYZER_SOCKS,
    Analyzer::ANALYZER_SSH,
    Analyzer::ANALYZER_DTLS,
    Analyzer::ANALYZER_SSL,
    Analyzer::ANALYZER_STEPPINGSTONE,
    Analyzer::ANALYZER_SYSLOG,
    Analyzer::ANALYZER_CONTENTLINE,
    Analyzer::ANALYZER_CONTENTS,
    Analyzer::ANALYZER_TCP,
    Analyzer::ANALYZER_TCPSTATS,
    Analyzer::ANALYZER_TEREDO,
    Analyzer::ANALYZER_UDP,
    Analyzer::ANALYZER_VXLAN,
    Analyzer::ANALYZER_XMPP,
    Analyzer::ANALYZER_ZIP,
    Analyzer::ANALYZER_TELNET,
    Analyzer::ANALYZER_RSH
};

export{
	# Create an ID for our new stream. By convention, this is
	# called "HOST_INFO_LOG".
	redef enum Log::ID += { HOST_INFO_LOG,
                            SUMMARY_HOST_LOG,
                            NET_EVENTS_LOG,
                            ATTACK_PATTERN_EVENT_LOG };# NET_EVENTS_LOG记录重要网络事件(或者网络包),作为KG分析的输入,BRO脚本分析多步攻击的数据集

    # 攻击模式更关注拓扑结构,没有大量的实际数据属性,借用一下zeek的日志输出功能,转化为易于使用的模式点,模式边文件
    # 不如只记录边,点边一起更新
    type pattern_event: record{
        name: string    &log;# 事件两端的点的标签名字,attack_pattern_n的模式
        id: int     &log;# 同一模式下有多个边,每个边再用id区分
        event_type: string     &log;# 与基本事件的类型对应
        edge_content: string    &log;# 设为形同"1>2"的字符串,分解后先加边,后加点,1和2含在点的name中
    };

    # 定义三元组中谓语的类型,输出的格式是HOST_INFO::ICMP_ECHO_REQUEST
    # 增加事件,需要修改三处,第一处是relation类型,第二处是写日志的rec3,第三处是generate_graph.py中的边标签(改两个地方)
    type relation: enum {
        Empty, ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY, ICMP_UNREACHABLE, RPC_REPLY, RPC_CALL, PORTMAP, NEW_CONNECTION_CONTENTS,
        CONNECTION_SYN_PACKET, TCP_PACKET, CONNECTION_ESTABLISHED, CONNECTION_FIRST_ACK, CONNECTION_EOF, CONNECTION_FINISHED,
        CONNECTION_PENDING, LOGIN_OUTPUT_LINE, LOGIN_INPUT_LINE, LOGIN_CONFUSED, LOGIN_CONFUSED_TEXT, LOGIN_SUCCESS, RSH_REQUEST,
        RSH_REPLY, CONNECTION_ATTEMPT, LOGIN_TERMINAL, CONNECTION_HALF_FINISHED, LOGIN_DISPLAY, HTTP_EVENT, HTTP_STATS, HTTP_END_ENTITY,
        HTTP_MESSAGE_DONE, HTTP_CONTENT_TYPE, HTTP_ALL_HEADERS, HTTP_REPLY, HTTP_HEADER, HTTP_BEGIN_ENTITY, HTTP_ENTITY_DATA
    };
    # unfortunately, its json format is incorrect
    # We need to handle the json format output line by line
    # redef LogAscii::use_json = T;
	# Define the record type that will contain the data to log.
    type host_info: record{
        ts: time    &log;
        ip: addr      &log;#indicates the newest ip
        ips: string     &default="" &log; # historical ips, ordered by their
        username: string    &default="" &log;
        hostname: string    &default="" &log;
        mac: string     &default="" &log;
        os: string      &default="" &log;
        description: string     &default="" &log;
        protocols: string   &default="" &log; # list all of its protocols
    };

    # 再定义一个结构体,用于存储三元组事件(A, relation, B),实际就是(主,谓,宾)三元组
    # 三元组事件的存储方案: 1.三元组表 2.水平表 3.属性表 4.垂直划分 5.六重索引 6.DB2RDF 
    # 还是存储到RDF中,后续可以进行SPARQL查询?
    # 数据量巨大,考虑三元组的聚合(去除一些没用的三元组)=>类比南理工的文章中的经验聚合(去除一些不太重要的告警信息)
    # 三元组的内容不局限于最底层流量,应当有一些告警层面的三元组(但是这种三元组从哪儿来?有现成的事件还是推理出来)

    # 更新: 用边来表示事件,为了兼容各种情况,可以包含诸多属性
    # 属性可以慢慢添加,逐渐完善
    # 目前考虑的事件: 1. icmp ping事件
    type event_info: record{
        ts: time    &log;
        real_time: string   &log;
        event_type: relation    &log;
        src_ip: addr    &log;
        src_p: port     &log;
        dst_ip: addr    &log;
        dst_p: port     &log;
        description: string &default="" &log;
    };
}

# Use it to store host-info
global hostlist: vector of host_info = {};
global events_not_recorded: table[string] of count = {};
global num_packets = 0;

function record_event(s: string){
    if(s in events_not_recorded){
        events_not_recorded[s] += 1;
    } else {
        events_not_recorded[s] = 1;
    }
}

# Precondition: 0 <= index <= |hostlist|
# Postcondition: cooresponding item has been updated
function update_single_host(hinfo: HOST_INFO::host_info, protocol: string, index: int){
    # remember to initialize "ips" and "protocols"
    # print fmt("update index %d", index);
    # print hinfo;
    # print fmt("index is : %d", index);
    local tmp_ip: string = fmt("%s", hinfo$ip);
    local up_index: count = 0;
    # print fmt("the ip is %s", tmp_ip);
    if(hostlist[index]$ips == ""){
        # print fmt("initialize ips of index %d", index);
        local t: time = network_time();
        hostlist[index]$ips = fmt("%s", strftime("%Y-%m-%d-%H:%M:%S|", t) + tmp_ip);
    }
    if(hostlist[index]$protocols == ""){
        # print fmt("initialize protocols of index %d", index);
        hostlist[index]$protocols = protocol + ":1";
    }
    # check that whether ip is the newest ip
    if(hinfo$ip != hostlist[index]$ip){
        # print fmt("update ips because host's ip has been changed");
        # Maybe this host uses a new ip now, so I need to concatenate "ips"
        # Since these messages comes in order, I take it for granted that it is unnecessary to compare timestamp.
        hostlist[index]$ip = hinfo$ip; # update the newest ip
        # maybe we need a new way to determine whether the ip is new: edit the if condition
        if(tmp_ip !in hostlist[index]$ips){
            # a new ip comes, append it to the end of ips
            local t1: time = network_time();
            hostlist[index]$ips += fmt(",%s", strftime("%Y-%m-%d-%H:%M:%S|", t1) + tmp_ip);
            print "append ips";
        } else {
            print "update ips";
            # in this case, the previous ts should be updated
            local comma: pattern = /,/;
            local tmp_tlb: string_vec = split_string(hostlist[index]$ips, comma);
            local ori_len: count = |tmp_tlb|;
            # tmp_tlb_ip holds the ips in tmp_tlb and has the same index as tmp_tlb
            # To ensure the coming ip is a new ip or not clearly.
            local tmp_tlb_ip: string_vec;
            for(key in tmp_tlb){
                local bin_tlb: string_vec = split_string(tmp_tlb[key], /\|/);
                tmp_tlb_ip[key] = bin_tlb[2];
            }
            # print fmt("previous len: %d", ori_len);
            # print "what is in ips now ?";
            # print hostlist[index]$ips;
            # print "what is in  tmp_tlb now?";
            # print tmp_tlb;
            for(key in tmp_tlb_ip){# use tmp_tlb_ip to determine the key to store
                print key;    # To avoid missing ips, we should initialize "ips" when we append a new item
                print tmp_tlb_ip[key];
                print "start checking";
                if(tmp_ip == tmp_tlb_ip[key]){
                    # this item should be updated
                    print "bingo";
                    # here is strange segment fault when I try to directly overwrite tmp_tlb[key] here
                    # so I record the value of key instead
                    up_index = key;
                    # tmp_tlb[key] = fmt("%s", strftime("%Y-%m-%d-%H:%M:%S|", t2) + tmp_ip);
                    # print fmt("the last item: %s", tmp_tlb[key]);
                    # if(key == ori_len){ # the last item
                    #     tmp_tlb[key] = fmt("%s", strftime("%Y-%m-%d-%H:%M:%S|", t2) + tmp_ip);
                    #     print fmt("the last item: %s", tmp_tlb[key]);
                    # }
                    # else{ # previous items
                    #     tmp_tlb[key] = fmt("%s", strftime("%Y-%m-%d-%H:%M:%S|", t2) + tmp_ip);
                    #     print fmt("previous item: %s", tmp_tlb[key]);
                    # }
                }
                print "end checking";
            }
            print "before join!";
            if(up_index != 0){
                # up_index is applied to update tmp_tlb
                # from now on, tmp_tlb_ip is useless
                local t2: time = network_time();
                tmp_tlb[up_index] = fmt("%s", strftime("%Y-%m-%d-%H:%M:%S|", t2) + tmp_ip);
            }
            # for(key in tmp_tlb){
            #     print fmt("[%d]=>%s", key, tmp_tlb[key]);
            # }
            # hostlist[index]$ips = cat_string_array(tmp_tlb); # overwrite
            hostlist[index]$ips = join_string_vec(tmp_tlb, ",");
            # print fmt("after join:%s", hostlist[index]$ips);
            # recheck the number of commas in ips
            if(ori_len != |split_string(hostlist[index]$ips, comma)|){
                print "Unexpected error: the number of commas is wrong";
                print fmt("ori_len: %d, new len: %d", ori_len, |split_string(hostlist[index]$ips, comma)|);
            }
        }
    } 
    # else {
    #     print "do not update ips";
    # }
    # check that whether protocol is a protocol related to this host
    # if not: concatenate "protocols"   separated by commas
    # this check condition is not so good
    # we'd better split protocols into individual items and compare them
    up_index = 0; # reinitialize up_index
    if(protocol != "" && protocol !in hostlist[index]$protocols){
        # print fmt("update protocols because a new protocol of this host found");
        hostlist[index]$protocols += fmt(",%s:1", protocol);
    } else {
        # record the count
        # print hostlist[index]$protocols;
        local pro_tlb: string_vec = split_string(hostlist[index]$protocols, /,/);
        local pro_tlb_tmp: string_vec;
        # print "start updating protocols";
        # print pro_tlb;
        for(key in pro_tlb){
            local bin_p_tlb: string_vec = split_string(pro_tlb[key], /:/);
            # print bin_p_tlb;
            pro_tlb_tmp[key] = bin_p_tlb[1];
        }
        for(key in pro_tlb_tmp){
            if(protocol == pro_tlb_tmp[key]){
                # increase by one later
                up_index = key;
            }
            if(up_index != 0){
                local bin_p_tlb1: string_vec = split_string(pro_tlb[up_index], /:/);
                local num_s: string = bin_p_tlb1[2];
                local num_v: count = to_count(num_s);
                num_v += 1;
                pro_tlb[up_index] = fmt("%s:%d", bin_p_tlb1[1], num_v);
            }
            # for(key in pro_tlb){
            #     print fmt("[%d]=>%s", key, pro_tlb[key]);
            # }
            hostlist[index]$protocols = join_string_vec(pro_tlb, ",");
        }
    }
    # update timestamp
    hostlist[index]$ts = hinfo$ts;
    # update hostname iff a different hostname comes
    if(hinfo$hostname != "" && hinfo$hostname != hostlist[index]$hostname){
        # in the case of empty string, initialize it
        # print fmt("initialize the hostname field of this host");
        hostlist[index]$hostname = hinfo$hostname;
    }
    # update os
    if(hinfo$os != "" && hinfo$os != hostlist[index]$os){
        # print fmt("update os field of this host");
        hostlist[index]$os = hinfo$os;
    }
    # update mac
    # Although we confirm that mac should be set as the unique id, 
    # we reconsider it in the second branch in update_hostlist.
    if(hinfo$mac != "" && hostlist[index]$mac == ""){
        # initialize mac field
        # print fmt("initialize mac field of this host");
        hostlist[index]$mac = hinfo$mac;
    }
    # update username
    if(hinfo$username != "" && hostlist[index]$username == ""){
        # print fmt("update username field of this host");
        hostlist[index]$username = hinfo$username;
    }
}

# Precondition: hinfo comes from fragmentary records
# Postcondition: update contents of hostlist with hinfo
function update_hostlist(hinfo: HOST_INFO::host_info, protocol: string){
    # print "prepare to update";
    local has_updated: bool = F;
    if(hinfo$mac != "" || hinfo$hostname != ""){ 
        # I believe that mac addresses and hostnames can uniquely identify a host.
        for(i in hostlist){
            if(((hostlist[i]$mac == hinfo$mac) && (hinfo$mac != "")) || ((hostlist[i]$hostname == hinfo$hostname) && (hinfo$hostname != ""))){
                # update
                update_single_host(hinfo, protocol, i);
                has_updated = T;
                break;
            }
        }
        if(!has_updated) {
            # To avoid missing ips, we should initialize "ips" when we append a new item
            hostlist[|hostlist|] = hinfo;
            local wall_time: time = network_time();
            local tmp_ip: string = fmt("%s", hinfo$ip);
            # 这边应该也要-1
            hostlist[|hostlist|-1]$ips += fmt("%s", strftime("%Y-%m-%d-%H:%M:%S|", wall_time) + tmp_ip);
            has_updated = T;
        }
    }
    # 为了icmp发现的主机能进入记录,暂时允许把ip作为主机唯一性考量
    if(hinfo ?$ ip){
        for(i in hostlist){
            if(hostlist[i]$ip == hinfo$ip){# 如果有,更新一下,其实没有什么好更新的
            # print hostlist[i]$ip;
            # print hinfo$ip;
                update_single_host(hinfo, protocol, i);
                has_updated = T;
                break;
            }
        }
        # 如果没有,插入
        if(!has_updated){
            # print "a new ip comes";
            # print hinfo$ip;
            # print |hostlist|;
            hostlist[|hostlist|] = hinfo;
            # print |hostlist|;
            local wall_time1: time = network_time();
            local tmp_ip1: string = fmt("%s", hinfo$ip);
            # print hostlist[|hostlist|-1];
            # |hostlist|改变了,再对齐对应记录作修改,后面-1
            hostlist[|hostlist|-1]$ips += fmt("%s", strftime("%Y-%m-%d-%H:%M:%S|", wall_time1) + tmp_ip1);
            has_updated = T;
            # 针对仅有ip的主机更新情况,不会再去下一个if分支
        }
    }
    if(!has_updated){
        # In this case, I can't confirm that this host
        for(i in hostlist){
            if(hinfo$ip == hostlist[i]$ip){
                update_single_host(hinfo, protocol, i);
                has_updated = T;
                break;
            }
        }
        if(!has_updated){
            # At this point, all correct info should have been updated
            print "incomplete information, skip it ", hinfo;
        }
    }
}

function update_network_event(c: connection, host_description: string, protocol: string, event_description: string, event_type_para: relation){
    event_counts += 1;
    print fmt("%d event(s) occurred.", event_counts);
    # 记录资产,主机即资产
    if(c$id ?$ orig_h && c$id ?$ resp_h){
        local rec1: HOST_INFO::host_info = [$ts = network_time(), $ip = c$id$orig_h, $description = host_description];
        local rec2: HOST_INFO::host_info = [$ts = network_time(), $ip = c$id$resp_h, $description = host_description];
        update_hostlist(rec1, protocol);
        Log::write(HOST_INFO::HOST_INFO_LOG, rec1);
        update_hostlist(rec2, protocol);
        Log::write(HOST_INFO::HOST_INFO_LOG, rec2);
    }
    # 记录事件,事件以边的形式呈现,必须连接两个点
    local t: time = network_time();
    local rec3: HOST_INFO::event_info = [$ts = network_time(), $real_time = fmt("%s", strftime("%Y-%m-%d-%H:%M:%S", t)), 
                                        $event_type = event_type_para, $src_ip = c$id$orig_h, $src_p = c$id$orig_p, 
                                        $dst_ip = c$id$resp_h, $dst_p = c$id$resp_p, $description = event_description];# 具体进行了哪个进程和端口的转换,从c参数看不出来,需要pm相关的事件提供
    # icmp_echo_reply的地址内容应该和icmp_echo_request的地址内容反过来
    if(host_description == "icmp_echo_reply"){
        rec3$src_ip = c$id$resp_h;
        rec3$src_p = c$id$resp_p;
        rec3$dst_ip = c$id$orig_h;
        rec3$dst_p = c$id$orig_p;
    }
    Log::write(HOST_INFO::NET_EVENTS_LOG, rec3);    
}

function check_ssh_hostname(id: conn_id, uid: string, host: addr){
    when(local hostname = lookup_addr(host)){
        local rec: HOST_INFO::host_info = [$ts = network_time(), $ip = host, $hostname = hostname, $description = "shh_auth"];
        update_hostlist(rec, "ssh");
        Log::write(HOST_INFO::HOST_INFO_LOG, rec);
    }
}

# event OS_version_found(c: connection, host: addr, OS: OS_version){
#     # print "an operating system has been fingerprinted";
#     # print fmt("the host running this OS is %s", host);
#     # print OS;
#     if(OS$genre != "UNKNOWN"){
#         local os_detail = fmt("%s %s", OS$genre, OS$detail);
#         local rec: HOST_INFO::host_info = [$ts = network_time(), $ip = host, $os = os_detail, $description = "OS_version_found"];
#         update_hostlist(rec, "os_fingerprint");
#         Log::write(HOST_INFO::HOST_INFO_LOG, rec);
#     }
#     # e.g [genre=UNKNOWN, detail=, dist=36, match_type=direct_inference]
#     # How to utilize this message?
# }

# There is no point in removing dulipcated messages for a specific ip. 
# Becuase ip addresses should not be the unique identification of a specific host.
# We should identity a specific host by ip and mac pairs which have the lastest network time.
event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string){
    # print "arp reply";
    # print fmt("source mac: %s, destination mac: %s, SPA: %s, SHA: %s, TPA: %s, THA: %s", mac_src, mac_dst, SPA, SHA, TPA, THA);
    # record ip and its mac address
    # we don't these form of mac addresses:
    # 00:00:00:00:00:00 and ff:ff:ff:ff:ff:ff
    if(SHA != "ff:ff:ff:ff:ff:ff" && SHA != "00:00:00:00:00:00" && SPA != 0.0.0.0){
        local rec1: HOST_INFO::host_info = [$ts = network_time(), $ip = SPA, $mac = SHA, $description = "arp_reply" ];
        update_hostlist(rec1, "arp");
        Log::write(HOST_INFO::HOST_INFO_LOG, rec1);
    }
    if(THA != "ff:ff:ff:ff:ff:ff" && THA != "00:00:00:00:00:00" && TPA != 0.0.0.0){
        local rec2: HOST_INFO::host_info = [$ts = network_time(), $ip = TPA, $mac = THA, $description = "arp_reply" ];
        update_hostlist(rec2, "arp");
        Log::write(HOST_INFO::HOST_INFO_LOG, rec2);
    }
}

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string){
    record_event("arp_request");
    # print "arp request";
    # print fmt("source mac: %s, destination mac: %s, SPA: %s, SHA: %s, TPA: %s, THA: %s", mac_src, mac_dst, SPA, SHA, TPA, THA);
    if(SHA != "ff:ff:ff:ff:ff:ff" && SHA != "00:00:00:00:00:00" && SPA != 0.0.0.0){
        local rec1: HOST_INFO::host_info = [$ts = network_time(), $ip = SPA, $mac = SHA, $description = "arp_request" ];
        update_hostlist(rec1, "arp");
        Log::write(HOST_INFO::HOST_INFO_LOG, rec1);
    }
    if(THA != "ff:ff:ff:ff:ff:ff" && THA != "00:00:00:00:00:00" && TPA != 0.0.0.0){
        local rec2: HOST_INFO::host_info = [$ts = network_time(), $ip = TPA, $mac = THA, $description = "arp_request" ];
        update_hostlist(rec2, "arp");
        Log::write(HOST_INFO::HOST_INFO_LOG, rec2);
    }
}

event bad_arp(SPA: addr, SHA: string, TPA: addr, THA: string, explanation: string){
    record_event("bad_arp");
    print fmt("this arp packet is bad because: %s", explanation);
}

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options){
    # print "A dhcp message is coming!";
    # print msg;
    # print options;
    record_event("dhcp_message");
    if(options ?$ host_name && options ?$ addr_request && options ?$ client_id){ # It occurred once: missing client_id, check it in advance
        print "haha";
        # print options;
        local rec1: HOST_INFO::host_info = [$ts = network_time(), $ip = options$addr_request, $mac = options$client_id$hwaddr, $hostname = options$host_name, $description = "dhcp_message1" ];
        update_hostlist(rec1, "dhcp");
        Log::write(HOST_INFO::HOST_INFO_LOG, rec1);
    } else{
        if(msg$yiaddr != 0.0.0.0){
            local rec2: HOST_INFO::host_info = [$ts = network_time(), $ip = msg$yiaddr, $mac = msg$chaddr, $description = "dhcp_message2" ];
            update_hostlist(rec2, "dhcp");
            Log::write(HOST_INFO::HOST_INFO_LOG, rec2);
        }
    }
}


event ssh_auth_successful(c: connection, auth_method_none: bool){
    record_event("ssh_auth_successful");
	for ( host in set(c$id$orig_h, c$id$resp_h) )
	{
		check_ssh_hostname(c$id, c$uid, host);
	}
}

event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count){
    record_event("dns_query_reply");
    # print "here comes a dns query reply";
    # print c;
    # print msg;        
    # print query;      
    # print qtype;
}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr){
    record_event("dns_A_reply");
    # print "********************************TYPE A REPLY*********************";
    # print c;
    # print msg;#[id=0, opcode=0, rcode=0, QR=T, AA=T, TC=F, RD=F, RA=F, Z=0, num_queries=0, num_answers=1, num_auth=0, num_addl=0]
    # print ans;#[answer_type=1, query=brwa86bad339915.local, qtype=1, qclass=32769, TTL=4.0 mins]
    # print a;#192.168.1.108
    local rec: HOST_INFO::host_info = [$ts = network_time(), $ip = a, $hostname = ans$query, $description = "dns_A_reply" ];
    update_hostlist(rec, "dns");
    Log::write(HOST_INFO::HOST_INFO_LOG, rec);    
}

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr){
    record_event("dns_AAAA_reply");
    local rec: HOST_INFO::host_info = [$ts = network_time(), $ip = a, $hostname = ans$query, $description = "dns_AAAA_reply" ];
    update_hostlist(rec, "dns");
    Log::write(HOST_INFO::HOST_INFO_LOG, rec); 
}

# I want to get hostnames by event related to DNS.
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count){
    record_event("dns_message");
    # print "dns_message";
    # print "1";
    # print c$dns_state$pending_queries;
    if(c ?$dns_state){
        for(index1 in c$dns_state$pending_queries){
            # print "2";
            # print c$dns_state$pending_queries[index1];
            for(index2 in c$dns_state$pending_queries[index1]$vals){
                local rec: DNS::Info = c$dns_state$pending_queries[index1]$vals[index2];
                # print rec;
                if(rec ?$ answers){
                    print "It has answers!!!!";
                    print rec;
                }
                if(rec ?$ qtype_name){
                    switch(rec$qtype_name){
                        case "A":
                            # print "type A";
                            # print fmt("host %s's query field: %s", rec$id$orig_h, rec$query);
                            break;
                        case "AAAA":
                            # print "type AAAA";
                            break;
                        case "CNAME":
                            # print "type CNAME";
                            break;
                        case "PTR":
                            # print "type PTR";
                            break;
                        case "MX":
                            # print "type MX";
                            break;
                        case "NS":
                            # print "type NS";
                            break;
                        default:
                            # print fmt("unexpected type: %s", rec$qtype_name);
                            break;
                    }
                }
                # Unfortunately, it is not the hostname. :(
            }
        }
    }
}

event dns_mapping_valid(dm: dns_mapping){
    record_event("dns_mapping_valid");
    # print "dns_mapping_valid";
    # print dm;
}

event dns_mapping_altered(dm: dns_mapping, old_addrs: addr_set, new_addrs: addr_set){
    record_event("dns_mapping_altered");
    # print "dns_mapping_altered";
    # print dm;
}

event dns_mapping_lost_name(dm: dns_mapping){
    record_event("dns_mapping_lost_name");
    # print "dns_mapping_lost_name";
    # print dm;
}

event dns_mapping_new_name(dm: dns_mapping){
    record_event("dns_mapping_new_name");
    # print "dns_mapping_new_name";
    # print dm;
}

event dns_mapping_unverified(dm: dns_mapping){
    record_event("dns_mapping_unverified");
    # print "dns_mapping_unverified";
    # print dm;
}



event ntlm_authenticate(c: connection, request: NTLM::Authenticate){
    record_event("ntlm_authenticate");
    # print c;
    # print request;
    # if(request ?$ user_name){
    #     print fmt("username: %s", request$user_name);
    # }
}

# collect more protocol information here
event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count){
    record_event("protocol_confirmation");
    local src_ip: addr;
    local dst_ip: addr;
    local protocol: string;
    if(c$id ?$ orig_h && c$id ?$ resp_h){
        src_ip = c$id$orig_h;
        dst_ip = c$id$resp_h;
    }
    switch(atype){
        case Analyzer::ANALYZER_AYIYA:
            protocol = "ayiya";
            break;
        # case Analyzer::ANALYZER_BACKDOOR:
        #     protocol = "backdoor";
        #     break;
        case Analyzer::ANALYZER_BITTORRENT:
            protocol = "bittorrent";
            break;
        case Analyzer::ANALYZER_BITTORRENTTRACKER:
            protocol = "bittorrenttracker";
            break;
        case Analyzer::ANALYZER_CONNSIZE:
            protocol = "connsize";#??
            break;
        case Analyzer::ANALYZER_DCE_RPC:
            protocol = "dce_rpc";
            break;
        case Analyzer::ANALYZER_DHCP:
            protocol = "dhcp";
            break;
        case Analyzer::ANALYZER_DNP3_TCP:
            protocol = "dnp3_tcp";
            break;
        case Analyzer::ANALYZER_DNP3_UDP:
            protocol = "dnp3_udp";
            break;
        case Analyzer::ANALYZER_CONTENTS_DNS:
            protocol = "contents_dns";
            break;
        case Analyzer::ANALYZER_DNS:
            protocol = "dns";
            break;
        case Analyzer::ANALYZER_FTP_DATA:
            protocol = "ftp_data";
            break;
        case Analyzer::ANALYZER_IRC_DATA:
            protocol = "irc_data";
            break;
        case Analyzer::ANALYZER_FINGER:
            protocol = "finger";
            break;
        case Analyzer::ANALYZER_FTP:
            protocol = "ftp";
            break;
        case Analyzer::ANALYZER_FTP_ADAT:
            protocol = "ftp_adat";
            break;
        case Analyzer::ANALYZER_GNUTELLA:
            protocol = "gnutella";
            break;
        case Analyzer::ANALYZER_GSSAPI:
            protocol = "gssapi";
            break;
        case Analyzer::ANALYZER_GTPV1:
            protocol = "gtpv1";
            break;
        case Analyzer::ANALYZER_HTTP:
            protocol = "http";
            break;
        case Analyzer::ANALYZER_ICMP:
            protocol = "icmp";
            break;
        case Analyzer::ANALYZER_IDENT:
            protocol = "ident";
            break;
        case Analyzer::ANALYZER_IMAP:
            protocol = "imap";
            break;
        # case  Analyzer::ANALYZER_INTERCONN:
        #     protocol = "interconn";
        #     break;
        case Analyzer::ANALYZER_IRC:
            protocol = "irc";
            break;
        case Analyzer::ANALYZER_KRB:
            protocol = "krb";
            break;
        case Analyzer::ANALYZER_KRB_TCP:
            protocol = "krb_tcp";# the previous one is its substring, how to handle this situation?
            break;
        case Analyzer::ANALYZER_CONTENTS_RLOGIN:
            protocol = "contents_rlogin";
            break;
        case Analyzer::ANALYZER_CONTENTS_RSH:
            protocol = "contents_rsh";
            break;
        case Analyzer::ANALYZER_LOGIN:
            protocol = "login";
            break;
        case Analyzer::ANALYZER_NVT:
            protocol = "nvt";
            break;
        case Analyzer::ANALYZER_RLOGIN:
            protocol = "rlogin";
            break;
        case Analyzer::ANALYZER_RSH:
            protocol = "rsh";
            break;
        case Analyzer::ANALYZER_TELNET:
            protocol = "telnet";
            break;
        case Analyzer::ANALYZER_MODBUS:
            protocol = "modbus";
            break;
        case Analyzer::ANALYZER_MYSQL:
            protocol = "mysql";
            break;
        case Analyzer::ANALYZER_CONTENTS_NCP:
            protocol = "contents_ncp";
            break;
        case Analyzer::ANALYZER_NCP:
            protocol = "ncp";
            break;
        case Analyzer::ANALYZER_CONTENTS_NETBIOSSSN:
            protocol = "contents_netbiosssn";
            break;
        case Analyzer::ANALYZER_NETBIOSSSN:
            protocol = "netbiosssn";
            break;
        case Analyzer::ANALYZER_NTLM:
            protocol = "ntlm";
            break;
        case Analyzer::ANALYZER_NTP:
            protocol = "ntp";
            break;
        case Analyzer::ANALYZER_PIA_TCP:
            protocol = "pia_tcp";
            break;
        case Analyzer::ANALYZER_PIA_UDP:
            protocol = "pia_udp";
            break;
        case Analyzer::ANALYZER_POP3:
            protocol = "pop3";
            break;
        case Analyzer::ANALYZER_RADIUS:
            protocol = "radius";
            break;
        case Analyzer::ANALYZER_RDP:
            protocol = "rdp";
            break;
        case Analyzer::ANALYZER_RFB:
            protocol = "rfb";
            break;
        case Analyzer::ANALYZER_CONTENTS_NFS:
            protocol = "contents_nfs";
            break;
        case Analyzer::ANALYZER_CONTENTS_RPC:
            protocol = "contents_rpc";
            break;
        case Analyzer::ANALYZER_MOUNT:
            protocol = "mount";
            break;
        case Analyzer::ANALYZER_NFS:
            protocol = "nfs";
            break;
        case Analyzer::ANALYZER_PORTMAPPER:
            protocol = "portmapper";
            break;
        case Analyzer::ANALYZER_SIP:
            protocol = "sip";
            break;
        case Analyzer::ANALYZER_CONTENTS_SMB:
            protocol = "contents_smb";
            break;
        case Analyzer::ANALYZER_SMB:
            protocol = "smb";
            break;
        case Analyzer::ANALYZER_SMTP:
            protocol = "smtp";
            break;
        case Analyzer::ANALYZER_SNMP:
            protocol = "snmp";
            break;
        case Analyzer::ANALYZER_SOCKS:
            protocol = "socks";
            break;
        case Analyzer::ANALYZER_SSH:
            protocol = "ssh";
            break;
        case Analyzer::ANALYZER_DTLS:
            protocol = "dtls";
            break;
        case Analyzer::ANALYZER_SSL:
            protocol = "ssl";
            break;
        case Analyzer::ANALYZER_STEPPINGSTONE:
            protocol = "steppingstone";
            break;
        case Analyzer::ANALYZER_SYSLOG:
            protocol = "syslog";
            break;
        case Analyzer::ANALYZER_CONTENTLINE:
            protocol = "contentline";
            break;
        case Analyzer::ANALYZER_CONTENTS:
            protocol = "contents";
            break;
        case Analyzer::ANALYZER_TCP:
            protocol = "tcp";
            break;
        case Analyzer::ANALYZER_TCPSTATS:
            protocol = "tcpstats";
            break;
        case Analyzer::ANALYZER_TEREDO:
            protocol = "teredo";
            break;
        case Analyzer::ANALYZER_UDP:
            protocol = "udp";
            break;
        case Analyzer::ANALYZER_XMPP:
            protocol = "xmpp";
            break;
        case Analyzer::ANALYZER_ZIP:
            protocol = "zip";
            break;
        default:
            print "Unexpected error: unknown protocol type!";
            protocol = "error";
            break;
    }
    if(protocol == "error")
        return;
    # both endpoints share the same protocol
    local rec1: HOST_INFO::host_info = [$ts = network_time(), $ip = src_ip, $description = protocol ];
    local rec2: HOST_INFO::host_info = [$ts = network_time(), $ip = dst_ip, $description = protocol ];
    update_hostlist(rec1, protocol);
    update_hostlist(rec2, protocol);
    Log::write(HOST_INFO::HOST_INFO_LOG, rec1); 
    Log::write(HOST_INFO::HOST_INFO_LOG, rec2);
    # print "a new protocol is logged";
}

# try to get software info
# Unfortunately, they haven't been triggered
event software_unparsed_version_found(c: connection, host: addr, str: string){
    record_event("software_unparsed_version_found");
    # fill app record
}

# event software_version_found(c: connection, host: addr, s: software, descr: string){
#     # fill app record
# }

# 基本数据包
# A raw packet header, consisting of L2 header and everything in pkt_hdr. .
# 比起packet_contents,raw_packet提供的信息更少,而且bro提出这两个事件的开销很大

# event raw_packet(p: raw_pkt_hdr){
#     record_event("raw_packet");
# }

# 若不是portmap出问题,packet_contents也不要了,增加了很多不必要的开销
event packet_contents(c: connection, contents: string){
    # print "packet_contents!";
    # print c$id$resp_p;
    record_event("packet_contents");
    if(c$id$resp_p == 111/udp){
        # 这种情况视作一个rpc事件,对应phase2中的135个分组(总共148个)
        # 其实是对目标主机的111/udp端口进行端口扫描,bro没有提供这个事件,自己定制该事件
        # print "portmapper protocol";
        # print c;
        # print contents;
        portmapper_call(c);
        # num_packets += 1;
    } 
    # else {
    #     print c;
    #     num_packets += 1;
    # }
    # # print contents;
    # p_num -= 1;
}


# 数据集分析的事件,同样要关心里面涉及的主机信息
# 网络流量图谱的基于bro日志构建,转为Gremlin脚本(属性设定,加点加边)输出
# 网络流量图谱的分析计算依赖于Gremlin提供的强大的图计算能力

# XX 放弃Gremlin脚本,调用hugegraph的http API传送json数据完成图更新操作
# phase-1-dump 785个分组
event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string){
    # Generated for ICMP echo request messages.
    update_network_event(c, "icmp_echo_request", "icmp", "a-ping-request-message", ICMP_ECHO_REQUEST);
}

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string){
    # Generated for ICMP echo reply messages.
    update_network_event(c, "icmp_echo_reply", "icmp", "a-ping-reply-message", ICMP_ECHO_REPLY);
}

event icmp_time_exceeded(c: connection, icmp: icmp_conn, code: count, context: icmp_context){
    record_event("icmp_time_exceeded");
    # Generated for ICMP time exceeded messages.
}

event icmp_error_message(c: connection, icmp: icmp_conn, code: count, context: icmp_context){
    record_event("icmp_error_message");
    # Generated for all ICMPv6 error messages that are not handled separately with dedicated events.
    # Zeek’s ICMP analyzer handles a number of ICMP error messages directly with dedicated events.
    # This event acts as a fallback for those it doesn’t.
}

event icmp_neighbor_advertisement(c: connection, icmp: icmp_conn, router: bool, solicited: bool,
override: bool, tgt: addr, options: icmp6_nd_options){
    record_event("icmp_neighbor_advertisement");
    # Generated for ICMP neighbor advertisement messages.
}

event icmp_neighbor_solicitation(c: connection, icmp: icmp_conn, tgt: addr, options: icmp6_nd_options){
    record_event("icmp_neighbor_solicitation");
    # Generated for ICMP neighbor solicitation messages.
}

event icmp_packet_too_big(c: connection, icmp: icmp_conn, code: count, context: icmp_context){
    record_event("icmp_packet_too_big");
    # Generated for ICMPv6 packet too big messages.
}

event icmp_parameter_problem(c: connection, icmp: icmp_conn, code: count, context: icmp_context){
    record_event("icmp_parameter_problem");
    # Generated for ICMPv6 parameter problem messages.
}

event icmp_redirect(c: connection, icmp: icmp_conn, tgt: addr, dest: addr, options: icmp6_nd_options){
    record_event("icmp_redirect");
    # Generated for ICMP redirect messages.
}

event icmp_router_advertisement(c: connection, icmp: icmp_conn, cur_hop_limit: count, managed: bool,
other: bool, home_agent: bool, pref: count, proxy: bool, res: count, router_lifetime: interval,
reachable_time: interval, retrans_timer: interval, options: icmp6_nd_options){
    record_event("icmp_router_advertisement");
    # Generated for ICMP router advertisement messages.
}

event icmp_router_solicitation(c: connection, icmp: icmp_conn, options: icmp6_nd_options){
    record_event("icmp_router_solicitation");
    # Generated for ICMP router solicitation messages.
}

event icmp_sent(c: connection, icmp: icmp_conn){
    record_event("icmp_sent");
    # Generated for all ICMP messages that are not handled separately with dedicated ICMP events.
    # Zeek’s ICMP analyzer handles a number of ICMP messages directly with dedicated events.
    # This event acts as a fallback for those it doesn’t.
}

event icmp_sent_payload(c: connection, icmp: icmp_conn, payload: string){
    record_event("icmp_sent_payload");
    # The same as icmp_sent except containing the ICMP payload.
}

event icmp_unreachable(c: connection, icmp: icmp_conn, code: count, context: icmp_context){
    # Generated for ICMP destination unreachable messages.
    update_network_event(c, "icmp_unreachable", "icmp", "a-ping-failed", ICMP_UNREACHABLE);
}

# phase-2-dump 148个分组
# pm related

# ProtocolDetector::found_protocol

# 阶段2需要自己定义"事件"了,自带的事件没有触发
function portmapper_call(c: connection){
    update_network_event(c, "portmapper_call", "portmap", "SADMIND(100232)", PORTMAP);
}

# 从new_packet,packet_contents出发
event mount_proc_mnt(c: connection, info: MOUNT3::info_t, req: MOUNT3::dirmntargs_t, rep: MOUNT3::mnt_reply_t){
    record_event("mount_proc_mnt");
    # Generated for MOUNT3 request/reply dialogues of type mnt.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out. MOUNT is a service running on top of RPC.
}

event mount_proc_not_implemented(c: connection, info: MOUNT3::info_t, proc: MOUNT3::proc_t){
    record_event("mount_proc_not_implemented");
    # Generated for MOUNT3 request/reply dialogues of a type that Zeek’s MOUNTv3 analyzer does not implement.
}

event mount_proc_null(c: connection, info: MOUNT3::info_t){
    record_event("mount_proc_null");
    # Generated for MOUNT3 request/reply dialogues of type null.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out. MOUNT is a service running on top of RPC.
}

event mount_proc_umnt(c: connection, info: MOUNT3::info_t, req: MOUNT3::dirmntargs_t){
    record_event("mount_proc_umnt");
    # Generated for MOUNT3 request/reply dialogues of type umnt.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out. MOUNT is a service running on top of RPC.
}

event mount_proc_umnt_all(c: connection, info: MOUNT3::info_t, req: MOUNT3::dirmntargs_t){
    record_event("mount_proc_umnt_all");
    # Generated for MOUNT3 request/reply dialogues of type umnt_all.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out. MOUNT is a service running on top of RPC.
}

event mount_reply_status(n: connection, info: MOUNT3::info_t){
    record_event("mount_reply_status");
    # Generated for each MOUNT3 reply message received, reporting just the status included.
}

event nfs_proc_create(c: connection, info: NFS3::info_t, req: NFS3::diropargs_t, rep: NFS3::newobj_reply_t){
    record_event("nfs_proc_create");
    # Generated for NFSv3 request/reply dialogues of type create.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out.
}

event nfs_proc_getattr(c: connection, info: NFS3::info_t, fh: string, attrs: NFS3::fattr_t){
    record_event("nfs_proc_getattr");
    # Generated for NFSv3 request/reply dialogues of type getattr.
    # The event is generated once we have either seen both the request
    # and its corresponding reply, or an unanswered request has timed out.
}

event nfs_proc_link(c: connection, info: NFS3::info_t, req: NFS3::linkargs_t, rep: NFS3::link_reply_t){
    record_event("nfs_proc_link");
    # Generated for NFSv3 request/reply dialogues of type link.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out.
}

event nfs_proc_lookup(c: connection, info: NFS3::info_t, req: NFS3::diropargs_t, rep: NFS3::lookup_reply_t){
    record_event("nfs_proc_lookup");
    # Generated for NFSv3 request/reply dialogues of type lookup.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out.
}

event nfs_proc_mkdir(c: connection, info: NFS3::info_t, req: NFS3::diropargs_t, rep: NFS3::newobj_reply_t){
    record_event("nfs_proc_mkdir");
    # Generated for NFSv3 request/reply dialogues of type mkdir.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out.
}

event nfs_proc_not_implemented(c: connection, info: NFS3::info_t, proc: NFS3::proc_t){
    record_event("nfs_proc_not_implemented");
    # Generated for NFSv3 request/reply dialogues of a type that Zeek’s NFSv3 analyzer does not implement.
}

event nfs_proc_null(c: connection, info: NFS3::info_t){
    record_event("nfs_proc_null");
    # Generated for NFSv3 request/reply dialogues of type null.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out.
}

event nfs_proc_read(c: connection, info: NFS3::info_t, req: NFS3::readargs_t, rep: NFS3::read_reply_t){
    record_event("nfs_proc_read");
    # Generated for NFSv3 request/reply dialogues of type read.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out.
}

event nfs_proc_readdir(c: connection, info: NFS3::info_t, req: NFS3::readdirargs_t, rep: NFS3::readdir_reply_t){
    record_event("nfs_proc_readdir");
    # Generated for NFSv3 request/reply dialogues of type readdir.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out.
}

event nfs_proc_readlink(c: connection, info: NFS3::info_t, fh: string, rep: NFS3::readlink_reply_t){
    record_event("nfs_proc_readlink");
    # Generated for NFSv3 request/reply dialogues of type readlink.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out.
}

event nfs_proc_remove(c: connection, info: NFS3::info_t, req: NFS3::diropargs_t, rep: NFS3::delobj_reply_t){
    record_event("nfs_proc_remove");
    # Generated for NFSv3 request/reply dialogues of type remove.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out.
}

event nfs_proc_rename(c: connection, info: NFS3::info_t, req: NFS3::renameopargs_t, rep: NFS3::renameobj_reply_t){
    record_event("nfs_proc_rename");
    # Generated for NFSv3 request/reply dialogues of type rename.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out.
}

event nfs_proc_rmdir(c: connection, info: NFS3::info_t, req: NFS3::diropargs_t, rep: NFS3::delobj_reply_t){
    record_event("nfs_proc_rmdir");
    # Generated for NFSv3 request/reply dialogues of type rmdir.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out.
}

event nfs_proc_sattr(c: connection, info: NFS3::info_t, req: NFS3::sattrargs_t, rep: NFS3::sattr_reply_t){
    record_event("nfs_proc_sattr");
    # Generated for NFSv3 request/reply dialogues of type sattr.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out.
}

event nfs_proc_symlink(c: connection, info: NFS3::info_t, req: NFS3::symlinkargs_t, rep: NFS3::newobj_reply_t){
    record_event("nfs_proc_symlink");
    # Generated for NFSv3 request/reply dialogues of type symlink.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out.
}

event nfs_proc_write(c: connection, info: NFS3::info_t, req: NFS3::writeargs_t, rep: NFS3::write_reply_t){
    record_event("nfs_proc_write");
    # Generated for NFSv3 request/reply dialogues of type write.
    # The event is generated once we have either seen both the request and its corresponding reply,
    # or an unanswered request has timed out.
}

event nfs_reply_status(n: connection, info: NFS3::info_t){
    record_event("nfs_reply_status");
    # Generated for each NFSv3 reply message received, reporting just the status included.
}

#--上面是关于nfs的调用事件--

event pm_attempt_getport(r: connection, status: rpc_status, pr: pm_port_request){
    record_event("pm_attempt_getport");
    # Generated for failed Portmapper requests of type getport.
}

event pm_attempt_dump(r: connection, status: rpc_status){
    record_event("pm_attempt_dump");
    # Generated for failed Portmapper requests of type dump.
}

event pm_attempt_callit(r: connection, status: rpc_status, call: pm_callit_request){
    record_event("pm_attempt_callit");
    # Generated for failed Portmapper requests of type callit.
}

event pm_attempt_null(r: connection, status: rpc_status){
    record_event("pm_attempt_null");
    # Generated for failed Portmapper requests of type null.
}

event pm_attempt_set(r: connection, status: rpc_status, m: pm_mapping){
    record_event("pm_attempt_set");
    # Generated for failed Portmapper requests of type set.
}

event pm_attempt_unset(r: connection, status: rpc_status, m: pm_mapping){
    record_event("pm_attempt_unset");
    # Generated for failed Portmapper requests of type unset.
}

event pm_bad_port(r: connection, bad_p: count){
    record_event("pm_bad_port");
    # Generated for Portmapper requests or replies that include an invalid port number.
    # Since ports are represented by unsigned 4-byte integers,
    # they can stray outside the allowed range of 0–65535 by being >= 65536.
    # If so, this event is generated.
}

event pm_request_callit(r: connection, call: pm_callit_request, p: port){
    record_event("pm_request_callit");
    # Generated for Portmapper request/reply dialogues of type callit.
}

event pm_request_dump(r: connection, m: pm_mappings){
    record_event("pm_request_dump");
    # Generated for Portmapper request/reply dialogues of type dump.
}

event pm_request_getport(r: connection, pr: pm_port_request, p: port){
    record_event("pm_request_getport");
    # Generated for Portmapper request/reply dialogues of type getport.
}

event pm_request_null(r: connection){
    record_event("pm_request_null");
    # Generated for Portmapper requests of type null.
}

event pm_request_set(r: connection, m: pm_mapping, success: bool){
    record_event("pm_request_set");
    # Generated for Portmapper request/reply dialogues of type set.
}

event pm_request_unset(r: connection, m: pm_mapping, success: bool){
    record_event("pm_request_unset");
    # enerated for Portmapper request/reply dialogues of type unset.
}

event rpc_call(c: connection, xid: count, prog: count, ver: count, proc: count, call_len: count){
    record_event("rpc_call");
    # Generated for RPC call messages.
}

event rpc_dialogue(c: connection, prog: count, ver: count, proc: count, status: rpc_status, start_time: time, call_len: count, reply_len: count){
    record_event("rpc_dialogue");
    # Generated for RPC request/reply pairs.
    # The RPC analyzer associates request and reply by their transaction identifiers
    # and raises this event once both have been seen.
    # If there’s not a reply, this event will still be generated eventually on timeout.
    # In that case, status will be set to RPC_TIMEOUT.
}

# 这边的实现,有误,可以触发rpc_reply,但是参数c是rpc_call的
# 暂且认为rpc_reply触发代表出现了一对rpc调用
# zeek将在3.1.0版本修复此bug
# 这里不调用update_network_event
event rpc_reply(c: connection, xid: count, status: rpc_status, reply_len: count){
    # print c;
    # print status;
    # 记录资产,主机即资产
    # Generated for RPC reply messages.
    if(c$id ?$ orig_h && c$id ?$ resp_h){
        local rec1: HOST_INFO::host_info = [$ts = network_time(), $ip = c$id$orig_h, $description = "rpc_reply"];
        local rec2: HOST_INFO::host_info = [$ts = network_time(), $ip = c$id$resp_h, $description = "rpc_reply"];
        update_hostlist(rec1, "rpc");
        Log::write(HOST_INFO::HOST_INFO_LOG, rec1);
        update_hostlist(rec2, "rpc");
        Log::write(HOST_INFO::HOST_INFO_LOG, rec2);
    }
    # 记录事件,事件以边的形式呈现,必须连接两个点
    # 先处理RPC_CALL事件
    local t: time = network_time();
    local rec3: HOST_INFO::event_info = [$ts = network_time(), $real_time = fmt("%s", strftime("%Y-%m-%d-%H:%M:%S", t)), 
                                        $event_type = RPC_CALL, $src_ip = c$id$orig_h, $src_p = c$id$orig_p, 
                                        $dst_ip = c$id$resp_h, $dst_p = c$id$resp_p, $description = fmt("%s", status)];
    Log::write(HOST_INFO::NET_EVENTS_LOG, rec3);
    # 然后处理RPC_REPLY事件,源ip与目的ip颠倒,源端口与目的端口颠倒,但是发出的rpc_reply的节点的源端口不是111(被映射为一个未知端口,展示需要,先设为一个较大的数)
    t = network_time();
    local random_port: int = rand(65535);# 为展示需要设置一个虚假的源端口
    while(random_port < 40000){
        random_port = rand(65535);
    }
    local tmp_str: string = fmt("%d", random_port) + "/udp";
    local fake_port: port = to_port(tmp_str);

    rec3 = [$ts = network_time(), $real_time = fmt("%s", strftime("%Y-%m-%d-%H:%M:%S", t)), 
                                        $event_type = RPC_REPLY, $src_ip = c$id$resp_h, $src_p = fake_port, 
                                        $dst_ip = c$id$orig_h, $dst_p = c$id$orig_p, $description = fmt("%s", status)];
    Log::write(HOST_INFO::NET_EVENTS_LOG, rec3);
    # num_packets += 1;
}
# 上面是关于pm和rpc的,可惜一个都没有触发
# 考虑包内容中有resp_p=111/udp,其中111是portmapper的端口号得知此包与portmapper相关
# 如何通过bro得知rpc调用了sadmind守护进程?

# phase-3-dump 530个分组
# 阶段3涉及的主要协议有SADMIND,Portmap,TCP,TELNET
# 先添加TCP和TELNET相关的事件,希望TELNET相关的事件可以触发
# 一些关于TCP重传之类的非常频繁且价值不大的事件,可以考虑直接过滤掉
event new_connection_contents(c: connection){
    # Generated when reassembly starts for a TCP connection. 
    # This event is raised at the moment when Zeek’s TCP analyzer enables stream reassembly for a connection.
    update_network_event(c, "new_connection_contents", "tcp", "reassembly-starts-for-a-TCP-connection", CONNECTION_SYN_PACKET);# 具体进行了哪个进程和端口的转换,从c参数看不出来,需要pm相关的事件提供
}

event connection_attempt(c: connection){
    # record_event("connection_attempt");
    # Generated for an unsuccessful connection attempt.
    # This event is raised when an originator unsuccessfully attempted to establish a connection.
    # “Unsuccessful” is defined as at least tcp_attempt_delay seconds having elapsed 
    # since the originator first sent a connection establishment packet to the destination without seeing a reply.
    update_network_event(c, "connection_attempt", "tcp", "an-unsuccessful-connection-attempt", CONNECTION_ATTEMPT);
}

event connection_established(c: connection){
    # Generated when seeing a SYN-ACK packet from the responder in a TCP handshake.
    # An associated SYN packet was not seen from the originator side if its state is not set to TCP_ESTABLISHED.
    # The final ACK of the handshake in response to SYN-ACK may or may not occur later,
    # one way to tell is to check the history field of connection to see if the originator sent an ACK,
    # indicated by ‘A’ in the history string.
    update_network_event(c, "connection_established", "tcp", "see-a-synack-packet-from-a-tcp-handshake", CONNECTION_ESTABLISHED);
}

event partial_connection(c: connection){
    record_event("partial_connection");
    # Generated for a new active TCP connection if Zeek did not see the initial handshake.
    # This event is raised when Zeek has observed traffic from each endpoint,
    # but the activity did not begin with the usual connection establishment.
}

event connection_partial_close(c: connection){
    record_event("connection_partial_close");
    # Generated when a previously inactive endpoint attempts to close a TCP connection
    # via a normal FIN handshake or an abort RST sequence.
    # When the endpoint sent one of these packets, 
    # Zeek waits tcp_partial_close_delay prior to generating the event,
    # to give the other endpoint a chance to close the connection normally.
}

event connection_finished(c: connection){
    # Generated for a TCP connection that finished normally.
    # The event is raised when a regular FIN handshake from both endpoints was observed.
    update_network_event(c, "connection_finished", "tcp", "a-tcp-connection-finished-normally", CONNECTION_FINISHED);
}

event connection_half_finished(c: connection){
    # record_event("connection_half_finished");
    # Generated when one endpoint of a TCP connection attempted to gracefully close the connection,
    # but the other endpoint is in the TCP_INACTIVE state.
    # This can happen due to split routing, in which Zeek only sees one side of a connection.
    update_network_event(c, "connection_half_finished", "tcp", "This-can-happen-due-to-split-routing", CONNECTION_HALF_FINISHED);
}

event connection_rejected(c: connection){
    record_event("connection_rejected");
    # Generated for a rejected TCP connection.
    # This event is raised when an originator attempted to setup a TCP connection
    # but the responder replied with a RST packet denying it.
}

event connection_reset(c: connection){
    record_event("connection_reset");
    # Generated when an endpoint aborted a TCP connection.
    # The event is raised when one endpoint of an established TCP connection aborted by sending a RST packet.
}

event connection_pending(c: connection){
    # Generated for each still-open TCP connection when Zeek terminates.
    update_network_event(c, "connection_pending", "tcp", "a-still-open-tcp-connection", CONNECTION_PENDING);
}

event connection_SYN_packet(c: connection, pkt: SYN_packet){
    # Generated for a SYN packet.
    # Zeek raises this event for every SYN packet seen by its TCP analyzer.
    update_network_event(c, "connection_SYN_packet", "tcp", "a-SYN-packet-appears", CONNECTION_SYN_PACKET);
}

event connection_first_ACK(c: connection){
    # Generated for the first ACK packet seen for a TCP connection from its originator.
    update_network_event(c, "connection_first_ack", "tcp", "the-first-ack-packet-seen-in-this-tcp-connection", CONNECTION_FIRST_ACK);
}

event connection_EOF(c: connection, is_orig: bool){
    # Generated at the end of reassembled TCP connections.
    # The TCP reassembler raised the event once for each endpoint of a connection
    # when it finished reassembling the corresponding side of the communication.
    update_network_event(c, "connection_eof", "tcp", "the-end-of-reassembled-tcp-connections", CONNECTION_EOF);
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string){
    # Generated for every TCP packet.
    # This is a very low-level and expensive event that should be avoided when at all possible.
    # It’s usually infeasible to handle when processing even medium volumes of traffic in real-time.
    # It’s slightly better than new_packet because it affects only TCP, but not much.
    # That said, if you work from a trace and want to do some packet-level analysis, it may come in handy.

    # 这一条开销太大了,如果价值不大,就删掉
    update_network_event(c, "tcp_packet", "tcp", "a-tcp-packet-appears", TCP_PACKET);
}

event tcp_option(c: connection, is_orig: bool, opt: count, optlen: count){
    record_event("tcp_option");
    # Generated for each option found in a TCP header.
    # Like many of the tcp_* events, this is a very low-level event and potentially expensive as it may be raised very often.
}

event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string){
    record_event("tcp_contents");
    # Generated for each chunk of reassembled TCP payload.
    # When content delivery is enabled for a TCP connection
    # (via tcp_content_delivery_ports_orig, tcp_content_delivery_ports_resp,
    # tcp_content_deliver_all_orig, tcp_content_deliver_all_resp),
    # this event is raised for each chunk of in-order payload reconstructed from the packet stream.
    # Note that this event is potentially expensive if many connections carry significant
    # amounts of data as then all that data needs to be passed on to the scripting layer.
}

event tcp_rexmit(c: connection, is_orig: bool, seq: count, len: count, data_in_flight: count, window: count){
    record_event("tcp_rexmit");
    # Generated for each detected TCP segment retransmission.
}

event tcp_multiple_checksum_errors(c: connection, is_orig: bool, threshold: count){
    record_event("tcp_multiple_checksum_errors");
    # Generated if a TCP flow crosses a checksum-error threshold, per ‘C’/’c’ history reporting.
}

event tcp_multiple_zero_windows(c: connection, is_orig: bool, threshold: count){
    record_event("tcp_multiple_zero_windows");
    # Generated if a TCP flow crosses a zero-window threshold, per ‘W’/’w’ history reporting.
}

event tcp_multiple_retransmissions(c: connection, is_orig: bool, threshold: count){
    record_event("tcp_multiple_retransmissions");
    # Generated if a TCP flow crosses a retransmission threshold, per ‘T’/’t’ history reporting.
}

event tcp_multiple_gap(c: connection, is_orig: bool, threshold: count){
    record_event("tcp_multiple_gap");
    # Generated if a TCP flow crosses a gap threshold, per ‘G’/’g’ history reporting.
}

event contents_file_write_failure(c: connection, is_orig: bool, msg: string){
    record_event("contents_file_write_failure");
    # Generated when failing to write contents of a TCP stream to a file.
}
# 以上是Zeek::TCP中的所有事件
# Zeek_Login.events.bif.zeek中应该含有关于RSH调用和TELNET的信息

event activating_encryption(c: connection){
    record_event("activating_encryption");
    # Generated for Telnet sessions when encryption is activated.
    # The Telnet protocol includes options for negotiating encryption.
    # When such a series of options is successfully negotiated,
    # the event engine generates this event.
}

event authentication_accepted(name: string, c: connection){
    record_event("authentication_accepted");
    # Generated when a Telnet authentication has been successful.
    # The Telnet protocol includes options for negotiating authentication.
    # When such an option is sent from client to server and the server replies that it accepts the authentication,
    # then the event engine generates this event.

    # Todo
    # Zeek’s current default configuration does not activate the protocol analyzer that generates this event;
    # the corresponding script has not yet been ported. To still enable this event, 
    # one needs to add a call to Analyzer::register_for_ports or a DPD payload signature.
}

event authentication_skipped(c: connection){
    record_event("authentication_skipped");
    # Generated for Telnet/Rlogin sessions when a pattern match indicates that
    # no authentication is performed.
}

event bad_option(c: connection){
    record_event("bad_option");
    # Generated for an ill-formed or unrecognized Telnet option.
}

event bad_option_termination(c: connection){
    record_event("bad_option_termination");
    # Generated for a Telnet option that’s incorrectly terminated.
}

event inconsistent_option(c: connection){
    record_event("inconsistent_option");
    # Generated for an inconsistent Telnet option.
    # Telnet options are specified by the client and server stating
    # which options they are willing to support vs. which they are not,
    # and then instructing one another which in fact they should
    # or should not use for the current connection.
    # If the event engine sees a peer violate either what
    # the other peer has instructed it to do,
    # or what it itself offered in terms of options in the past,
    # then the engine generates this event.
}

event login_confused(c: connection, msg: string, line: string){
    # Generated when tracking of Telnet/Rlogin authentication failed.
    # As Zeek’s login analyzer uses a number of heuristics to
    # extract authentication information, it may become confused.
    # If it can no longer correctly track the authentication dialog, it raises this event.
    update_network_event(c, "login_confused", "telnet", "tracking-of-Telnet/Rlogin-authentication-failed", LOGIN_CONFUSED);
}

event login_confused_text(c: connection, line: string){
    # Generated after getting confused while tracking
    # a Telnet/Rlogin authentication dialog.
    # The login analyzer generates this even for every line
    # of user input after it has reported login_confused for a connection.
    update_network_event(c, "login_confused_text", "telnet", "getting-confused-while-tracking-a-Telnet/Rlogin-authentication-dialog", LOGIN_CONFUSED_TEXT);
}

event login_display(c: connection, display: string){
    # record_event("login_display");
    # Generated for clients transmitting an X11 DISPLAY in a Telnet session.
    # This information is extracted out of environment variables sent as Telnet options.
    update_network_event(c, "login_display", "telnet", "clients-transmitting-an-X11-DISPLAY-in-a-Telnet-session", LOGIN_DISPLAY);
}

event login_failure(c: connection, user: string, client_user: string, password: string, line: string){
    record_event("login_failure");
    # Generated for Telnet/Rlogin login failures.
    # The login analyzer inspects Telnet/Rlogin sessions to heuristically extract
    # username and password information as well as the text returned by the login server.
    # This event is raised if a login attempt appears to have been unsuccessful.
}

event login_input_line(c: connection, line: string){
    # Generated for lines of input on Telnet/Rlogin sessions.
    # The line will have control characters (such as in-band Telnet options) removed.
    update_network_event(c, "login_input_line", "telnet", "lines-of-input-on-Telnet/Rlogin-sessions", LOGIN_INPUT_LINE);
}

event login_output_line(c: connection, line: string){
    # Generated for lines of output on Telnet/Rlogin sessions.
    # The line will have control characters (such as in-band Telnet options) removed.
    update_network_event(c, "login_output_line", "telnet", "lines-of-output-on-Telnet/Rlogin-sessions", LOGIN_OUTPUT_LINE);
}

event login_prompt(c: connection, prompt: string){
    record_event("login_prompt");
    # Generated for clients transmitting a terminal prompt in a Telnet session.
    # This information is extracted out of environment variables sent as Telnet options.
}

event login_success(c: connection, user: string, client_user: string, password: string, line: string){
    # Generated for successful Telnet/Rlogin logins.
    # The login analyzer inspects Telnet/Rlogin sessions to heuristically
    # extract username and password information as well as the text
    # returned by the login server.
    # This event is raised if a login attempt appears to have been successful.
    update_network_event(c, "login_success", "telnet", "successful-Telnet/Rlogin-logins", LOGIN_SUCCESS);
}

event login_terminal(c: connection, terminal: string){
    # record_event("login_terminal");
    # Generated for clients transmitting a terminal type in a Telnet session.
    # This information is extracted out of environment variables sent as Telnet options.
    update_network_event(c, "login_terminal", "telnet", "clients-transmitting-a-terminal-type-in-a-Telnet-session", LOGIN_TERMINAL);
}

# phase-4-dump 526个分组
# 该阶段攻击主机往目标主机上安装DDOS工具,大量触发rsh_request和rsh_reply事件

event rsh_reply(c: connection, client_user: string, server_user: string, line: string){
    # Generated for client side commands on an RSH connection.
    # See RFC 1258 for more information about the Rlogin/Rsh protocol.
    local des: string = fmt("rsh-connection-client_user:%s,server_user:%s", client_user, server_user);
    update_network_event(c, "rsh_reply", "rsh", des, RSH_REPLY);
}

event rsh_request(c: connection, client_user: string, server_user: string, line: string, new_session: bool){
    # Generated for client side commands on an RSH connection.
    # See RFC 1258 for more information about the Rlogin/Rsh protocol.
    local des: string = fmt("rsh-connection-client_user:%s,server_user:%s", client_user, server_user);
    update_network_event(c, "rsh_request", "rsh", des, RSH_REQUEST);
}
# 以上是Zeek提供的和TELNET相关的事件,有相当一部分事件需要自己激活(为其注册端口)

# phase-5-dump 分组最多的阶段 34553个分组 DDOS工具开始运作
# HTTP相关协议
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string){
    record_event("http_request");
    # Generated for HTTP requests.
    # Zeek supports persistent and pipelined HTTP sessions
    # and raises corresponding events as it parses client/server dialogues.
    # This event is generated as soon as a request’s initial line has been parsed,
    # and before any http_header events are raised.
}

event http_reply(c: connection, version: string, code: count, reason: string){
    # record_event("http_reply");
    # Generated for HTTP replies.
    # Zeek supports persistent and pipelined HTTP sessions
    # and raises corresponding events as it parses client/server dialogues.
    # This event is generated as soon as a reply’s initial line has been parsed,
    # and before any http_header events are raised.
    update_network_event(c, "http_reply", "http", "a-reply’s-initial-line-has-been-parsed", HTTP_REPLY);
}

event http_header(c: connection, is_orig: bool, name: string, value: string){
    # record_event("http_header");
    # Generated for HTTP headers.
    # Zeek supports persistent and pipelined HTTP sessions
    # and raises corresponding events as it parses client/server dialogues.
    update_network_event(c, "http_header", "http", "Generated-for-HTTP-headers", HTTP_HEADER);
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list){
    # record_event("http_all_headers");
    # Generated for HTTP headers, passing on all headers of
    # an HTTP message at once.
    # Zeek supports persistent and pipelined HTTP sessions
    # and raises corresponding events as it parses client/server dialogues.
    update_network_event(c, "http_all_headers", "http", "passing-on-all-headers-of-an-HTTP-message-at-once", HTTP_ALL_HEADERS);
}

event http_begin_entity(c: connection, is_orig: bool){
    # record_event("http_begin_entity");
    # Generated when starting to parse an HTTP body entity.
    # This event is generated at least once for each non-empty
    # (client or server) HTTP body; and potentially more than once
    # if the body contains further nested MIME entities.
    # Zeek raises this event just before it starts parsing each entity’s content.
    update_network_event(c, "http_begin_entity", "http", "generated-for-each non-empty-(client-or-server)-HTTP-body", HTTP_BEGIN_ENTITY);
}

event http_end_entity(c: connection, is_orig: bool){
    # record_event("http_end_entity");
    # Generated when finishing parsing an HTTP body entity.
    # This event is generated at least once for each non-empty
    # (client or server) HTTP body; and potentially more than once
    # if the body contains further nested MIME entities.
    # Zeek raises this event at the point when it has finished
    # parsing an entity’s content.
    update_network_event(c, "http_end_entity", "http", "finish-parsing-an-HTTP-body-entity", HTTP_END_ENTITY);
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string){
    # record_event("http_entity_data");
    # Generated when parsing an HTTP body entity, passing on the data.
    # This event can potentially be raised many times for each entity,
    # each time passing a chunk of the data of not further defined size.

    # A common idiom for using this event is to first reassemble the data
    # at the scripting layer by concatenating it to a successively growing string;
    # and only perform further content analysis once the corresponding http_end_entity event
    # has been raised. Note, however, that doing so can be quite expensive for HTTP tranders.
    # At the very least, one should impose an upper size limit on how much data is being buffered.
    update_network_event(c, "http_entity_data", "http", "pass-on-the-data", HTTP_ENTITY_DATA);
}

event http_content_type(c: connection, is_orig: bool, ty: string, subty: string){
    # record_event("http_content_type");
    # Generated for reporting an HTTP body’s content type.
    # This event is generated at the end of parsing an HTTP header,
    # passing on the MIME type as specified by the Content-Type header.
    # If that header is missing, this event is still raised with a default value of text/plain.
    update_network_event(c, "http_content_type", "http", "passing-on-the-MIME-typed", HTTP_CONTENT_TYPE);
}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat){
    # record_event("http_message_done");
    # Generated once at the end of parsing an HTTP message.
    # Zeek supports persistent and pipelined HTTP sessions and raises
    # corresponding events as it parses client/server dialogues.
    # A “message” is one top-level HTTP entity, such as a complete request or reply.
    # Each message can have further nested sub-entities inside.
    # This event is raised once all sub-entities belonging to a top-level message
    # have been processed (and their corresponding http_entity_* events generated).
    update_network_event(c, "http_message_done", "http", "a-top-level-message-have-been-processed", HTTP_MESSAGE_DONE);
}

event http_event(c: connection, event_type: string, detail: string){
    # record_event("http_event");
    # Generated for errors found when decoding HTTP requests or replies.
    update_network_event(c, "http_event", "http", detail, HTTP_EVENT);# 注意一下detail的内容
}

event http_stats(c: connection, stats: http_stats_rec){
    # record_event("http_stats");
    # Generated at the end of an HTTP session to report statistics about it.
    # This event is raised after all of an HTTP session’s requests and replies have been fully processed.
    update_network_event(c, "http_stats", "http", "an-http-session-finished-and-stats-generated", HTTP_STATS);
}

event http_connection_upgrade(c: connection, protocol: string){
    record_event("http_connection_upgrade");
    # Generated when a HTTP session is upgraded to a different protocol (e.g. websocket).
    # This event is raised when a server replies with a HTTP 101 reply.
    # No more HTTP events will be raised after this event.
}

# [http_entity_data] = 226,
# [http_begin_entity] = 55,
# [http_header] = 217,
# [http_reply] = 55,
# [http_all_headers] = 55,
# [http_content_type] = 55,
# [http_message_done] = 55,
# [http_end_entity] = 55,
# [http_stats] = 45,
# [http_event] = 24


function start_analyzers(){
    # enable RPC-based protocol analyzers
    Analyzer::register_for_ports(Analyzer::ANALYZER_PORTMAPPER, pm_ports);
    # enable telnet protocol analyzers
    Analyzer::register_for_ports(Analyzer::ANALYZER_TELNET, telnet_ports);
    # enable rsh protocol analyzers
    Analyzer::register_for_ports(Analyzer::ANALYZER_RSH, rsh_ports);
    # Analyzer::enable_analyzer(Analyzer::ANALYZER_TELNET);
    Analyzer::enable_analyzer(Analyzer::ANALYZER_PORTMAPPER);
    for(e in analyzer_tags){
        Analyzer::enable_analyzer(e);
    }
}


function attack_pattern_event_logger(){
    # 如果想实现数据独立性,考虑使用输入框架
    # 仔细想了一下,ping扫描事件根本就不需要reply啊
    # ping的太少也不行,稍微多一点才合适
    local attack_rel = string_vec("icmp_echo_ping|0>1", "icmp_echo_ping|0>2", "icmp_echo_ping|0>3", "icmp_echo_ping|0>4", "icmp_echo_ping|0>5", "icmp_echo_ping|0>6","icmp_echo_ping|0>7", "icmp_echo_ping|0>8", "icmp_echo_ping|0>9","icmp_echo_ping|0>10", "icmp_echo_ping|0>11", "icmp_echo_ping|0>12", "icmp_echo_reply|11>0");
    local tmp_n: int = 0;

    print attack_rel;
    while(tmp_n < |attack_rel|){
        # print type_name(item);
        local tmp_tlb: string_vec = split_string(attack_rel[tmp_n], /\|/);
        local rec: HOST_INFO::pattern_event = [$name="attack_pattern_0", $id=tmp_n, $event_type=tmp_tlb[0], $edge_content=tmp_tlb[1]];
        Log::write(HOST_INFO::ATTACK_PATTERN_EVENT_LOG, rec);
        tmp_n += 1;
    }
}

function attack_pattern_event_logger1(){
    # 如果想实现数据独立性,考虑使用输入框架
    local attack_rel = string_vec("portmap|0>1", "portmap|0>2", "rpc_call|0>1", "rpc_reply|1>0");# protmap|0>1会被覆盖
    local tmp_n: int = 0;

    print attack_rel;
    while(tmp_n < |attack_rel|){
        # print type_name(item);
        local tmp_tlb: string_vec = split_string(attack_rel[tmp_n], /\|/);
        local rec: HOST_INFO::pattern_event = [$name="attack_pattern_1", $id=tmp_n, $event_type=tmp_tlb[0], $edge_content=tmp_tlb[1]];
        Log::write(HOST_INFO::ATTACK_PATTERN_EVENT_LOG, rec);
        tmp_n += 1;
    }
}

function attack_pattern_event_logger2(){
    # 如果想实现数据独立性,考虑使用输入框架
    local attack_rel = string_vec("login_output_line|0>1", "login_confused|0>1", "login_success|0>1");# login_success代表root权限被获取,参考CVE-1999-0977
    local tmp_n: int = 0;

    print attack_rel;
    while(tmp_n < |attack_rel|){
        # print type_name(item);
        local tmp_tlb: string_vec = split_string(attack_rel[tmp_n], /\|/);
        local rec: HOST_INFO::pattern_event = [$name="attack_pattern_2", $id=tmp_n, $event_type=tmp_tlb[0], $edge_content=tmp_tlb[1]];
        Log::write(HOST_INFO::ATTACK_PATTERN_EVENT_LOG, rec);
        tmp_n += 1;
    }
}



function attack_pattern_logger(){
    Log::create_stream(HOST_INFO::ATTACK_PATTERN_EVENT_LOG, [$columns=pattern_event, $path="attack_pattern_event"]);
    attack_pattern_event_logger();
    attack_pattern_event_logger1();# 暂时这么弄
}

event zeek_init() &priority=10{
    start_analyzers();
    # Analyzer::register_for_ports(Analyzer::ANALYZER_CONTENTS_RPC, pm_ports);
    # Analyzer::enable_analyzer(Analyzer::ANALYZER_CONTENTS_RPC);
    # create our log stream at the very beginning
	Log::create_stream(HOST_INFO::HOST_INFO_LOG, [$columns=host_info, $path="host-info"]);
    # the other log stream to output of a summary of host-info
    Log::create_stream(HOST_INFO::SUMMARY_HOST_LOG, [$columns=host_info, $path="host-summary"]);
    # 同样地,建立KG要存储的内容的日志流
    Log::create_stream(HOST_INFO::NET_EVENTS_LOG, [$columns=event_info, $path="network_events"]);# kg_info存储"三元组"形式的知识
    # some useless fields are filtered
    local filter: Log::Filter = [$name="without_dscription", $path="simple_hosts",
                                $include=set("ip","hostname","username","mac","os","ips","protocols")];
    Log::add_filter(HOST_INFO::SUMMARY_HOST_LOG, filter);
}

event zeek_done(){
    print "finish";
    for(i in hostlist){
        local rec: HOST_INFO::host_info = hostlist[i];
        Log::write(HOST_INFO::SUMMARY_HOST_LOG, rec);
    }
    # local rec1: HOST_INFO::kg_info = [$ts=network_time(), $A=" ", $predicate=ICMP_ECHO_REQUEST, $B=" "];# 三元组日志测试数据
    # Log::write(HOST_INFO::NET_EVENTS_LOG, rec1);
    # print Analyzer::registered_ports(Analyzer::ANALYZER_CONTENTS_RPC);
    # print Analyzer::all_registered_ports();
    # print Analyzer::disabled_analyzers;
    # print likely_server_ports;
    # print num_packets;
    print events_not_recorded;
    attack_pattern_logger();
}

