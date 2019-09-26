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

# 2019.1.13
# Maintain the information of hosts all the time and output it to log file regularly

# 2019.1.14
# completed two functions named update_hostlist and update_single_host

# 2019.1.15
# event new_connection: collect various protocols which are indicated by connections
# event protocol_confirmation: this event is emitted when bro confirms that this protocol is actually running here
# problem to solve: whether the protocols comes is a new protocol? Using !in is not appropriate.

# 2019.1.16
# adjust the format of protocols   etc: http:33,dns:14
# data to log cannot be a table

# 2019.1.17
# how to invoke a event in a specific interval
# refer to test1.bro and define an event by ourself
# this user-defined event can complish the task of logging hostlist every n seconds
# outside dataprocesser can read the log every n seconds as well

# 2019.1.18 todo-list
# convert ts to the form of "YYYY:MM:DD-HH:MM:SS", which is easier to understand
# in "ips": mark the timestamp of each ip
# in "protocols": mark the number that indicate how many time this protocol has beem confirmed
# the value of n is dynamic
# there are some problems in updating ips
# 1. segment fault
# 2. redundant ip in "ips" field
# 3, three records missing ips(uninitialized)
# 4. the way to check a ip already exist? etc: 192.168.1.5, 192.168.1.50 substring is not reliable
module HOST_INFO;

export{
	# Create an ID for our new stream. By convention, this is
	# called "HOST_INFO_LOG".
	redef enum Log::ID += { HOST_INFO_LOG,
                            SUMMARY_HOST_LOG };

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
}

# Use it to store host-info
global hostlist: vector of host_info = {};


# Precondition: 0 <= index <= |hostlist|
# Postcondition: cooresponding item has been updated
function update_single_host(hinfo: HOST_INFO::host_info, protocol: string, index: int){
    # remember to initialize "ips" and "protocols"
    # print fmt("update index %d", index);
    # print hinfo;
    print fmt("index is : %d", index);
    local tmp_ip: string = fmt("%s", hinfo$ip);
    local up_index: count = 0;
    print fmt("the ip is %s", tmp_ip);
    if(hostlist[index]$ips == ""){
        # print fmt("initialize ips of index %d", index);
        local t: time = current_time();
        hostlist[index]$ips = fmt("%s", strftime("%Y-%m-%d %H:%M:%S|", t) + tmp_ip);
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
            local t1: time = current_time();
            hostlist[index]$ips += fmt(",%s", strftime("%Y-%m-%d %H:%M:%S|", t1) + tmp_ip);
            print "append ips";
        } else {
            print "update ips";
            # in this case, the previous ts should be updated
            local comma: pattern = /,/;
            local tmp_tlb: table[count] of string = split(hostlist[index]$ips, comma);
            local ori_len: count = |tmp_tlb|;
            # tmp_tlb_ip holds the ips in tmp_tlb and has the same index as tmp_tlb
            # To ensure the coming ip is a new ip or not clearly.
            local tmp_tlb_ip: table[count] of string;
            for(key in tmp_tlb){
                local bin_tlb: table[count] of string = split(tmp_tlb[key], /\|/);
                tmp_tlb_ip[key] = bin_tlb[2];
            }
            print fmt("previous len: %d", ori_len);
            print "what is in ips now ?";
            print hostlist[index]$ips;
            print "what is in  tmp_tlb now?";
            print tmp_tlb;
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
                    # tmp_tlb[key] = fmt("%s", strftime("%Y-%m-%d %H:%M:%S|", t2) + tmp_ip);
                    # print fmt("the last item: %s", tmp_tlb[key]);
                    # if(key == ori_len){ # the last item
                    #     tmp_tlb[key] = fmt("%s", strftime("%Y-%m-%d %H:%M:%S|", t2) + tmp_ip);
                    #     print fmt("the last item: %s", tmp_tlb[key]);
                    # }
                    # else{ # previous items
                    #     tmp_tlb[key] = fmt("%s", strftime("%Y-%m-%d %H:%M:%S|", t2) + tmp_ip);
                    #     print fmt("previous item: %s", tmp_tlb[key]);
                    # }
                }
                print "end checking";
            }
            print "before join!";
            if(up_index != 0){
                # up_index is applied to update tmp_tlb
                # from now on, tmp_tlb_ip is useless
                local t2: time = current_time();
                tmp_tlb[up_index] = fmt("%s", strftime("%Y-%m-%d %H:%M:%S|", t2) + tmp_ip);
            }
            for(key in tmp_tlb){
                print fmt("[%d]=>%s", key, tmp_tlb[key]);
            }
            # hostlist[index]$ips = cat_string_array(tmp_tlb); # overwrite
            hostlist[index]$ips = join_string_array(",", tmp_tlb);
            print fmt("after join:%s", hostlist[index]$ips);
            # recheck the number of commas in ips
            if(ori_len != |split(hostlist[index]$ips, comma)|){
                print "Unexpected error: the number of commas is wrong";
                print fmt("ori_len: %d, new len: %d", ori_len, |split(hostlist[index]$ips, comma)|);
            }
        }
    } else {
        print "do not update ips";
    }
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
        local pro_tlb: table[count] of string = split(hostlist[index]$protocols, /,/);
        local pro_tlb_tmp: table[count] of string;
        print "start updating protocols";
        print pro_tlb;
        for(key in pro_tlb){
            local bin_p_tlb: table[count] of string = split(pro_tlb[key], /:/);
            pro_tlb_tmp[key] = bin_p_tlb[1];
        }
        for(key in pro_tlb_tmp){
            if(protocol == pro_tlb_tmp[key]){
                # increase by one later
                up_index = key;
            }
            if(up_index != 0){
                local bin_p_tlb1: table[count] of string = split(pro_tlb[up_index], /:/);
                local num_s: string = bin_p_tlb1[2];
                local num_v: count = to_count(num_s);
                num_v += 1;
                pro_tlb[up_index] = fmt("%s:%d", bin_p_tlb1[1], num_v);
            }
            for(key in pro_tlb){
                print fmt("[%d]=>%s", key, pro_tlb[key]);
            }
            hostlist[index]$protocols = join_string_array(",", pro_tlb);
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
            hostlist[|hostlist|]$ips += fmt("%s", strftime("%Y-%m-%d %H:%M:%S|", wall_time) + tmp_ip);
            has_updated = T;
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

function check_ssh_hostname(id: conn_id, uid: string, host: addr){
    when(local hostname = lookup_addr(host)){
        local rec: HOST_INFO::host_info = [$ts = network_time(), $ip = host, $hostname = hostname, $description = "shh_auth"];
        update_hostlist(rec, "ssh");
        Log::write(HOST_INFO::HOST_INFO_LOG, rec);
    }
}

event OS_version_found(c: connection, host: addr, OS: OS_version){
    # print "an operating system has been fingerprinted";
    # print fmt("the host running this OS is %s", host);
    # print OS;
    if(OS$genre != "UNKNOWN"){
        local os_detail = fmt("%s %s", OS$genre, OS$detail);
        local rec: HOST_INFO::host_info = [$ts = network_time(), $ip = host, $os = os_detail, $description = "OS_version_found"];
        update_hostlist(rec, "os_fingerprint");
        Log::write(HOST_INFO::HOST_INFO_LOG, rec);
    }
    # e.g [genre=UNKNOWN, detail=, dist=36, match_type=direct_inference]
    # How to utilize this message?
}

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
    print fmt("this arp packet is bad because: %s", explanation);
}

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options){
    # print "A dhcp message is coming!";
    # print msg;
    # print options;
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
	for ( host in set(c$id$orig_h, c$id$resp_h) )
	{
		check_ssh_hostname(c$id, c$uid, host);
	}
}

event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count){
    # print "here comes a dns query reply";
    # print c;
    # print msg;        
    # print query;      
    # print qtype;
}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr){
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
    local rec: HOST_INFO::host_info = [$ts = network_time(), $ip = a, $hostname = ans$query, $description = "dns_AAAA_reply" ];
    update_hostlist(rec, "dns");
    Log::write(HOST_INFO::HOST_INFO_LOG, rec); 
}

# I want to get hostnames by event related to DNS.
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count){
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
    print "dns_mapping_valid";
    print dm;
}

event dns_mapping_altered(dm: dns_mapping, old_addrs: addr_set, new_addrs: addr_set){
    print "dns_mapping_altered";
    print dm;
}

event dns_mapping_lost_name(dm: dns_mapping){
    print "dns_mapping_lost_name";
    print dm;
}

event dns_mapping_new_name(dm: dns_mapping){
    print "dns_mapping_new_name";
    print dm;
}

event dns_mapping_unverified(dm: dns_mapping){
    print "dns_mapping_unverified";
    print dm;
}



event ntlm_authenticate(c: connection, request: NTLM::Authenticate){
    print c;
    print request;
    if(request ?$ user_name){
        print fmt("username: %s", request$user_name);
    }
}

# collect more protocol information here
event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count){
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
        case Analyzer::ANALYZER_BACKDOOR:
            protocol = "backdoor";
            break;
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
        case  Analyzer::ANALYZER_INTERCONN:
            protocol = "interconn";
            break;
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
    # fill app record
}

event software_version_found(c: connection, host: addr, s: software, descr: string){
    # fill app record
}

event bro_init() &priority=10{
    # create our log stream at the very beginning
	Log::create_stream(HOST_INFO::HOST_INFO_LOG, [$columns=host_info, $path="host-info"]);
    # the other log stream to output of a summary of host-info
    Log::create_stream(HOST_INFO::SUMMARY_HOST_LOG, [$columns=host_info, $path="host-summary"]);
    # some useless fields are filtered
    local filter: Log::Filter = [$name="without_dscription", $path="simple_hosts",
                                $include=set("ip","hostname","username","mac","os","ips","protocols")];
    Log::add_filter(HOST_INFO::SUMMARY_HOST_LOG, filter);
}

event bro_init(){
    print "start";
    # local a: addr = 123.123.123.123;
    # local host: HOST_INFO::host_info = [$ts = network_time(), $ip = a, $hostname = "testhost", $description = "test record" ];
    # update_hostlist(host, "dns");
}

event bro_done(){
    print "finish";
    for(i in hostlist){
        local rec: HOST_INFO::host_info = hostlist[i];
        Log::write(HOST_INFO::SUMMARY_HOST_LOG, rec);
    }
}