#!/usr/bin/env python
# -*- mode: python; coding: utf-8 -*-

"""IPFS nodes crawler"""
import ipfsApi
import ipaddress
from subprocess import check_output


def main():
    ipfs_diag_net()
    get_nodes_ids()
    get_nodes_info()


def ipfs_diag_net():
    """
    Gets raw output from:
    ipfs diag net 
    """
    with open("ipfs_diag_net", "w") as ipfs_diag_net_f:
        ipfs_diag_net_f.write(check_output("ipfs diag net", shell=True))
    ipfs_diag_net_f.close()



def get_nodes_ids():
    """
    Parsing nodes IDs 
    """
    with open("ipfs_diag_net", "r") as ipfs_diag_net_f:
        for line in ipfs_diag_net_f:
            line = line.strip()
            if line.startswith("ID"):
                with open("nodes_ids", "a") as nodes_ids_f:
                    nodes_ids_f.write(line.strip().split(" ")[1]+"\n")
        nodes_ids_f.close()
    ipfs_diag_net_f.close()


def get_nodes_info():
    """
    Gets raw info of the nodes parsed
    """
    ipfsClient = ipfsApi.Client('127.0.0.1', 5001)
    with open("nodes_ids", "r") as nodes_ids_f:
        for line in nodes_ids_f:
            try:
                node_info = ipfsClient.dht_findpeer(line.strip(), timeout=1)
                public_ips(node_info)
                with open("nodes_info", "a") as nodes_info_f:
                    nodes_info_f.write(node_info) 
            except:
                pass
    nodes_info_f.close()
    nodes_ids_f.close()


def public_ips(node_info):
    """
    Parsing public IPs from the raw node info
    """
    for i in range (0, len(node_info["Responses"])):
        for ip in node_info["Responses"][i]["Addrs"]:
            ip = ip.split("/")[2]
            if not ipaddress.ip_address(unicode(ip)).is_private:
                with open("nodes_ips", "a") as nodes_ips_f:
                    nodes_ips_f.write(ip + "\n")


if __name__ == "__main__":
    main()


