global n = 0;
global m = 0;
global p_num = 0;

# 基本数据包
event raw_packet(p: raw_pkt_hdr){
    print "raw_packet!";
    print p;
    p_num += 1;
}

event packet_contents(c: connection, contents: string){
    print "packet_contents!";
    print c;
    print contents;
    p_num -= 1;
}

# phase-1-dump
event icmp_echo_request(C: connection, icmp: icmp_conn, id: count, seq: count, payload: string){
    print "icmp_echo_request!";
    print icmp;
    n += 1;
}

event icmp_echo_reply(C: connection, icmp: icmp_conn, id: count, seq: count, payload: string){
    print "icmp_echo_reply!";
    print icmp;
    m += 1;
}

# phase-2-dump
# pm related
event pm_attempt_getport(r: connection, status: rpc_status, pr: pm_port_request){
    print "pm_attempt_getport!";
}

event pm_attempt_dump(r: connection, status: rpc_status){
    print "pm_attempt_dump!";
}

event pm_attempt_callit(r: connection, status: rpc_status, call: pm_callit_request){
    print "pm_attempt_callit!";
}

event pm_attempt_null(r: connection, status: rpc_status){
    print "pm_attempt_null!";
}

event pm_attempt_set(r: connection, status: rpc_status, m: pm_mapping){
    print "pm_attempt_set!";
}

event pm_attempt_unset(r: connection, status: rpc_status, m: pm_mapping){
    print "pm_attempt_unset!";
}

event pm_bad_port(r: connection, bad_p: count){
    print "pm_bad_port!";
}

event pm_request_callit(r: connection, call: pm_callit_request, p: port){
    print "pm_request_callit!";
}

event pm_request_dump(r: connection, m: pm_mappings){
    print "pm_request_dump!";
}

event pm_request_getport(r: connection, pr: pm_port_request, p: port){
    print "pm_request_getport!";
}

event pm_request_null(r: connection){
    print "pm_request_null!";
}

event pm_request_set(r: connection, m: pm_mapping, success: bool){
    print "pm_request_set!";
}

event pm_request_unset(r: connection, m: pm_mapping, success: bool){
    print "pm_request_unset!";
}

event rpc_call(C: connection, xid: count, prog: count, ver: count, proc: count, call_len: count){
    print "rpc_call!";
}

event rpc_dialogue(c: connection, prog: count, ver: count, proc: count, status: rpc_status, start_time: time, call_len: count, reply_len: count){
    print "rpc_dialogue!";
}

event rpc_reply(c: connection, xid: count, status: rpc_status, reply_len: count){
    print "rpc_reply!";
}

# phase-3-dump

# phase-4-dump

# phase-5-dump


event bro_init(){
    print "Let's start!";
}

event bro_done(){
    print "Over.";
    print n;
    print m;
    print p_num;
}