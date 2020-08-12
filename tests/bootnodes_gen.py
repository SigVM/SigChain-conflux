#!/usr/bin/env python3
import sys
import os
import shlex, subprocess, signal # for running the node processes
from conflux.utils import *

if (len(sys.argv) != 2):
    sys.exit("arg number is not matched")
num_of_bootnodes=int(sys.argv[1])
pri_key_list = []
node_id_list = []
for _ in range(num_of_bootnodes):
    pri_key, pub_key = ec_random_keys()
    node_id = encode_hex(encode_int32(pub_key[0]) + encode_int32(pub_key[1]))
    #print(encode_hex(pri_key), node_id)
    pri_key_list.extend([encode_hex(pri_key)])
    node_id_list.extend([node_id])
BOOTNODE_URL = []
for i in range(len(pri_key_list)):
    BOOTNODE_URL.extend(["cfxnode://"+str(node_id_list[i])+"@127.0.0.1:"+str(32323+i)])
for i in range(len(pri_key_list)):
    os.system("rm -rf ../run_multinodes_dev_" + str(i))
    os.system("cp -r ../run_multinodes_dev ../run_multinodes_dev_" + str(i))
    fin = open("../run_multinodes_dev/development.toml", "rt")
    fout = open("../run_multinodes_dev_" + str(i) + "/development.toml", "wt")
    bootnodes = 'bootnodes="'
    first = True
    for j in range(len(BOOTNODE_URL)):
        if (i!=j):
            if first:
                bootnodes += BOOTNODE_URL[j]
                first = False
            else:
                bootnodes += "," + BOOTNODE_URL[j]
    bootnodes += '"'
    #print(bootnodes)
    new_data = ""
    for line in fin:
        if(line.find("bootnodes=")!=-1):
            new_data += bootnodes + "\n"
        elif(line.find("public_tcp_port=32323")!=-1):
            new_data += "public_tcp_port=" + str(32323+i) + "\n"
        elif(line.find("tcp_port=32323")!=-1):
            new_data += "tcp_port=" + str(32323+i) + "\n"
        elif(line.find("udp_port=32323")!=-1):
            new_data += "udp_port=" + str(32323+i) + "\n"
        elif(line.find("net_key=")!=-1):
            new_data += 'net_key="' + pri_key_list[i] + '"\n'
        elif(line.find("jsonrpc_local_http_port=12539")!=-1):
            new_data += "jsonrpc_local_http_port=" + str(12539+i) + "\n"
        else:
            new_data += line
    fin.close()
    fout.write(new_data)
    fout.close()

# execute shell commands to run the nodes
process_list = []
try:
    for i in range(num_of_bootnodes):
        node_dir = '../run_multinodes_dev_' + str(i)
        log_file_path = node_dir + '/temp.log'
        log_file = open(log_file_path, "w")
        cmd = '../target/debug/conflux --config ../run_multinodes_dev_' + str(i) + '/development.toml'
        args = shlex.split(cmd)
        a = subprocess.Popen(args, stdout=log_file, cwd = node_dir)
        process_list.extend([a])
    process_list[0].wait()
except KeyboardInterrupt:
    for i in range(len(process_list)):
        os.kill(process_list[i].pid, signal.SIGTERM)
