#!/usr/bin/env python
# -*- mode: python; coding: utf-8 -*-

"""IPFS nodes crawler"""
import ipfsApi
import ipaddress
import subprocess


def main():
    node_ids_set = get_nodes_ids(ipfs_diag_net())
    get_nodes_info(node_ids_set)
        

def ipfs_diag_net():
    """
    Gets raw output from:
    ipfs diag net 
    """
    return subprocess.check_output("ipfs diag net", shell=True)


def get_nodes_ids(ipfs_diag_net_out):
    """
    Parsing nodes IDs 
    """
    node_ids_set = set()
    for line in ipfs_diag_net_out.split("\n"):
        line = line.strip()
        if line.startswith("ID"):
            line = line.strip().split(" ")[1]
            node_ids_set.add(line)
    return node_ids_set


def get_nodes_info(node_ids_set):
    """
    Gets raw info of the nodes parsed
    """
    ipfsClient = ipfsApi.Client('127.0.0.1', 5001)
    node_info_list = list()
    for set_item in node_ids_set:    
        try:
            node_info = ipfsClient.dht_findpeer(set_item, timeout=1)
            public_ips(node_info)
        except:
            pass


def public_ips(node_info):
    """
    Parsing public IPs from the raw node info
    """
    ips_set = set()
    for i in range (0, len(node_info["Responses"])):
        for ip in node_info["Responses"][i]["Addrs"]:
            ip = ip.split("/")[2]
            if not ipaddress.ip_address(unicode(ip)).is_private:
                ips_set.add(ip)
    set_to_file(ips_set, "nodes_ips", "a") 


def set_to_file(_set, file_name, mode):
    """
    helper function for writing set() elements to the file
    """
    for set_item in _set:
        with open(file_name, mode) as file_name_f:
            file_name_f.write(set_item + "\n")
        file_name_f.close()


def geolocation():
    pass


if __name__ == "__main__":
    main()


