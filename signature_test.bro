signature my-first-sig{
    ip-proto == tcp
    dst-port == 80
    payload /.*root/
    event "Found root!"
}

event signature_match(state: signature_state, msg: string, data: string){
    
}