#!/usr/bin/env python
# -*- mode: python; coding: utf-8 -*-


"""IPFS nodes crawler"""
import ipfsApi
import ipaddress
import subprocess


def main():
    """
    The main heartbeat
    """
    node_ids_set = get_nodes_ids(ipfs_diag_net())
    nodes_info_list = get_nodes_info(node_ids_set)
    for node_info in nodes_info_list:
        try:
            ips_set = public_ips(node_info)
            iteratable_space_to_file(ips_set, "nodes_ips", "a")
        except:
            print "Some errors"


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
            node_info = ipfs_client.dht_findpeer(set_item, timeout=1)
        except:
            print "Some errors"
        node_info_list.append(node_info)
    return node_info_list


def public_ips(node_info):
    """
    Parsing public IPs from the raw node info
    """
    ips_set = set()
    for i in range(0, len(node_info["Responses"])):
        for node_ip in node_info["Responses"][i]["Addrs"]:
            node_ip = node_ip.split("/")[2]
            if not ipaddress.ip_address(unicode(node_ip)).is_private:
                ips_set.add(node_ip)
    return ips_set


def iteratable_space_to_file(iteratable_space, file_name, mode):
    """
    helper function for writing iteratable space's elements to the file
    """
    for item in iteratable_space:
        with open(file_name, mode) as file_name_f:
            file_name_f.write(item + "\n")
    file_name_f.close()


def geolocation():
    """
    Geolocation function (goeip)
    """
    pass


if __name__ == "__main__":
    main()


