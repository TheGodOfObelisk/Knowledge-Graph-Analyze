@load /usr/local/bro/share/bro/base/bif/plugins/Bro_RPC.events.bif.bro


global n = 0;
global m = 0;
global p_num = 0;
global k = 0;

# 基本数据包
# A raw packet header, consisting of L2 header and everything in pkt_hdr. .
event raw_packet(p: raw_pkt_hdr){
    # print "raw_packet!";
    # print p;
    # if(p?$l2){
    #     print p$l2;
    # } else {
    #     print "no l2";
    # }
    # if(p?$ip){
    #     print p$ip;
    # } else {
    #     print "no ip field";
    # }
    # if(p?$ip6){
    #     print p$ip6;
    # } else {
    #     print "no ip6 field";
    # }
    # if(p?$tcp){
    #     print p$tcp;
    # } else {
    #     print "no tcp field";
    # }
    # if(p?$udp){
    #     print p$udp;
    # } else {
    #     print "no udp field";
    # }
    # if(p?$icmp){
    #     print p$icmp;
    # } else {
    #     print "no icmp field";
    # }
    p_num += 1;
}

event packet_contents(c: connection, contents: string){
    print "packet_contents!";
    # print c$id$resp_p;
    if(c$id$resp_p == 111/udp){
        print "portmapper protocol";
    } else {
        print c$id$resp_p;
    }
    # print contents;
    # p_num -= 1;
}

# phase-1-dump
event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string){
    # print "icmp_echo_request!";
    # print icmp;
    n += 1;
}

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string){
    print "icmp_echo_reply!";
    # print icmp;
    m += 1;
}

event icmp_time_exceeded(c: connection, icmp: icmp_conn, code: count, context: icmp_context){
    print "icmp_time_exceeded!";
    k += 1;
}

event icmp_error_message(c: connection, icmp: icmp_conn, code: count, context: icmp_context){
    print "icmp_error_message!";
}

event icmp_neighbor_advertisement(c: connection, icmp: icmp_conn, router: bool, solicited: bool,
override: bool, tgt: addr, options: icmp6_nd_options){
    print "icmp_neighbor_advertisement!";
}

event icmp_neighbor_solicitation(c: connection, icmp: icmp_conn, tgt: addr, options: icmp6_nd_options){
    print "icmp_neighbor_solicitation!";
}

event icmp_packet_too_big(c: connection, icmp: icmp_conn, code: count, context: icmp_context){
    print "icmp_packet_too_big!";
}

event icmp_parameter_problem(c: connection, icmp: icmp_conn, code: count, context: icmp_context){
    print "icmp_parameter_problem!";
}

event icmp_redirect(c: connection, icmp: icmp_conn, tgt: addr, dest: addr, options: icmp6_nd_options){
    print "icmp_redirect!";
}

event icmp_router_advertisement(c: connection, icmp: icmp_conn, cur_hop_limit: count, managed: bool,
other: bool, home_agent: bool, pref: count, proxy: bool, res: count, router_lifetime: interval,
reachable_time: interval, retrans_timer: interval, options: icmp6_nd_options){
    print "icmp_router_advertisement!";
}

event icmp_router_solicitation(c: connection, icmp: icmp_conn, options: icmp6_nd_options){
    print "icmp_router_solicitation!";
}

event icmp_sent(c: connection, icmp: icmp_conn){
    print "icmp_sent!";
}

event icmp_sent_payload(c: connection, icmp: icmp_conn, payload: string){
    print "icmp_sent_payload!";
}

event icmp_unreachable(c: connection, icmp: icmp_conn, code: count, context: icmp_context){
    print "icmp_unreachable!";
}
# phase-2-dump
# pm related
event mount_proc_mnt(c: connection, info: MOUNT3::info_t, req: MOUNT3::dirmntargs_t, rep: MOUNT3::mnt_reply_t){
    print "mount_proc_mnt!";
}

event mount_proc_not_implemented(c: connection, info: MOUNT3::info_t, proc: MOUNT3::proc_t){
    print "mount_proc_not_implemented!";
}

event mount_proc_null(c: connection, info: MOUNT3::info_t){
    print "mount_proc_null!";
}

event mount_proc_umnt(c: connection, info: MOUNT3::info_t, req: MOUNT3::dirmntargs_t){
    print "mount_proc_umnt!";
}

event mount_proc_umnt_all(c: connection, info: MOUNT3::info_t, req: MOUNT3::dirmntargs_t){
    print "mount_proc_umnt_all!";
}

event mount_reply_status(n: connection, info: MOUNT3::info_t){
    print "mount_reply_status!";
}

event nfs_proc_create(c: connection, info: NFS3::info_t, req: NFS3::diropargs_t, rep: NFS3::newobj_reply_t){
    print "nfs_proc_create!";
}

event nfs_proc_getaddr(c: connection, info: NFS3::info_t, fh: string, attrs: NFS3::fattr_t){
    print "nfs_proc_getaddr!";
}

event nfs_proc_link(c: connection, info: NFS3::info_t, req: NFS3::linkargs_t, rep: NFS3::link_reply_t){
    print "nfs_proc_link!";
}

event nfs_proc_lookup(c: connection, info: NFS3::info_t, req: NFS3::diropargs_t, rep: NFS3::lookup_reply_t){
    print "nfs_proc_lookup!";
}

event nfs_proc_mkdir(c: connection, info: NFS3::info_t, req: NFS3::diropargs_t, rep: NFS3::newobj_reply_t){
    print "nfs_proc_mkdir!";
}

event nfs_proc_not_implemented(c: connection, info: NFS3::info_t, proc: NFS3::proc_t){
    print "nfs_proc_not_implemented!";
}

event nfs_proc_null(c: connection, info: NFS3::info_t){
    print "nfs_proc_null!";
}

event nfs_proc_read(c: connection, info: NFS3::info_t, req: NFS3::readargs_t, rep: NFS3::read_reply_t){
    print "nfs_proc_read!";
}

event nfs_proc_readdir(c: connection, info: NFS3::info_t, req: NFS3::readdirargs_t, rep: NFS3::readdir_reply_t){
    print "nfs_proc_readdir!";
}

event nfs_proc_readlink(c: connection, info: NFS3::info_t, fh: string, rep: NFS3::readlink_reply_t){
    print "nfs_proc_readlink!";
}

event nfs_proc_remove(c: connection, info: NFS3::info_t, req: NFS3::diropargs_t, rep: NFS3::delobj_reply_t){
    print "nfs_proc_remove!";
}

event nfs_proc_rename(c: connection, info: NFS3::info_t, req: NFS3::renameopargs_t, rep: NFS3::renameobj_reply_t){
    print "nfs_proc_rename!";
}

event nfs_proc_rmdir(c: connection, info: NFS3::info_t, req: NFS3::diropargs_t, rep: NFS3::delobj_reply_t){
    print "nfs_proc_rmdir!";
}

event nfs_proc_sattr(c: connection, info: NFS3::info_t, req: NFS3::sattrargs_t, rep: NFS3::sattr_reply_t){
    print "nfs_proc_sattr!";
}

event nfs_proc_symlink(c: connection, info: NFS3::info_t, req: NFS3::symlinkargs_t, rep: NFS3::newobj_reply_t){
    print "nfs_proc_symlink!";
}

event nfs_proc_write(c: connection, info: NFS3::info_t, req: NFS3::writeargs_t, rep: NFS3::write_reply_t){
    print "nfs_proc_write!";
}

event nfs_reply_status(n: connection, info: NFS3::info_t){
    print "nfs_reply_status!";
}

#--上面是关于nfs的调用事件--

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
# 上面是关于pm和rpc的,可惜一个都没有触发
# 考虑包内容中有resp_p=111/udp,其中111是portmapper的端口号得知此包与portmapper相关
# 如何通过bro得知rpc调用了sadmind守护进程?

event udp_contents(u: connection, is_orig: bool, contents: string){
    print "udp_contents!";
    print u;
}
# 测试一下udp事件

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
    print k;
    print p_num;
}