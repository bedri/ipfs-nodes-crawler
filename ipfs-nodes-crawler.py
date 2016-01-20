#!/usr/bin/env python
# -*- mode: python; coding: utf-8 -*-

"""IPFS nodes crawler"""
import ipfsApi
import ipaddress
import json
from subprocess import check_output


ipfsClient = ipfsApi.Client('127.0.0.1', 5001)

def ipfs_diag_net():
    """
    Gets raw output from
    ipfs diag net 
    """
    with open("ipfs_diag_net", "w") as ipfs_diag_net_f:
        ipfs_diag_net_f.write(check_output("ipfs diag net", shell=True))
    ipfs_diag_net_f.close()

def get_nodes_ids():
    """
    Parses nodes IDs from ipfs diag net output
    """
    with open("ipfs_diag_net", "r") as ipfs_diag_net_f:
        for line in ipfs_diag_net_f:
            line = line.strip()
            if line.startswith("ID"):
                with open("nodes_ids", "a") as nodes_ids_f:
                    peer_ids_f.write(line.strip().split(" ")[1]+"\n")
                #get_peer_ips(line.strip().split(" ")[1])
            #print line.strip().split(" ")[1]
        nodes_ids_f.close()
    ipfs_diag_net_f.close()


def get_nodes_info():
    """
    Gets raw info of the nodes parsed from ipfs diag net output
    """
    with open("nodes_ids", "r") as nodes_ids_f:
        for line in nodes_ids_f:
            try:
                node_info = ipfsClient.dht_findpeer(line.strip(), timeout=1)
                public_ips(node_info)
                with open("nodes_info", "a") as nodes_info_f:
                    nodes_info_f.write(peer_info) 
            except:
                pass
        nodes_info_f.close()
    nodes_ids_f.close()



def public_ips(node_info):
    for i in range (0, len(node_info["Responses"])):
        for ip in node_info["Responses"][i]["Addrs"]:
            ip = ip.split("/")[2]
            if not ipaddress.ip_address(unicode(ip)).is_private:
                print ip



#ipfs_diag_net()
#get_nodes_ids()
get_nodes_info()
#public_ips()

