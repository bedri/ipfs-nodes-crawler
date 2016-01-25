#!/usr/bin/env python
# -*- mode: python; coding: utf-8 -*-


"""IPFS nodes crawler"""
import ipfsApi
import ipaddress
import subprocess
from geoip import geolite2

def main():
    """
    The main heartbeat
    """
        
    node_ids_set = get_nodes_ids(ipfs_diag_net())
    nodes_info_list = get_nodes_info(node_ids_set)
    ips_set = set()
    for node_info in nodes_info_list:
        try:
            ips_list = get_ips(node_info)
            for node_ip in ips_list:
                if not ipaddress.ip_address(unicode(node_ip)).is_private:
                    ips_set.add(node_ip)
        except:
            print "Some errors"
    iteratable_space_to_file(ips_set, "nodes_ips", "a")
    print geolocation(ips_set)
    nodes_geolocation = geolocation(ips_set)
    for node in nodes_geolocation:
        print node.country
        print node.location

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
    Returns list of raw info of the nodes
    """
    ipfs_client = ipfsApi.Client('127.0.0.1', 5001)
    node_info_list = list()
    for set_item in node_ids_set:
        try:
            node_info = ipfs_client.dht_findpeer(set_item, timeout=5)
        except:
            print "Some errors"
        node_info_list.append(node_info)
    return node_info_list


def get_ips(node_info):
    """
    Parsing IPs from the raw node info
    """
    ips_list = list()
    for i in range(0, len(node_info["Responses"])):
        for node_ip in node_info["Responses"][i]["Addrs"]:
            node_ip = node_ip.split("/")[2]
            ips_list.append(node_ip)
    return ips_list


def iteratable_space_to_file(iteratable_space, file_name, mode):
    """
    helper function for writing iteratable space's elements to the file
    """
    for item in iteratable_space:
        with open(file_name, mode) as file_name_f:
            file_name_f.write(item + "\n")
    file_name_f.close()


def geolocation(ips_set):
    """
    Geolocation function
    """
    geolocation_list = list() 
    for node_ip in ips_set:
        try:
            match = geolite2.lookup(node_ip)
            if match is not None:
                geolocation_list.append(match)
        except:
            pass
    return geolocation_list


if __name__ == "__main__":
    main()


