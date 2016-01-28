#!/usr/bin/env python
# -*- mode: python; coding: utf-8 -*-


"""IPFS nodes crawler"""
import ipfsApi
import ipaddress
import subprocess
import pymongo
from geoip import geolite2

def main():
    """
    The main heartbeat
    """
    nodes_ids_set = get_nodes_ids(ipfs_diag_net())
    nodes_info_list = get_nodes_info(nodes_ids_set)
    ips_set = set()
    for node_info in nodes_info_list:
        try:
            ips_list = get_ips(node_info)
            for node_ip in ips_list:
                if not ipaddress.ip_address(unicode(node_ip)).is_private:
                    ips_set.add(node_ip)
        except:
            print "Some errors"
    """
    iteratable_space_to_file(nodes_ids_set, "nodes_ids", "a")
    iteratable_space_to_file(ips_set, "nodes_ips", "a")
    iteratable_space_to_file(nodes_info_list, "nodes_info", "a")
    """
    iteratable_space_to_output(nodes_ids_set)
    iteratable_space_to_output(ips_set)
    iteratable_space_to_output(nodes_info_list)
    nodes_geolocation = geolocation(ips_set)
    mongo_client = pymongo.MongoClient()
    ipfs_db = mongo_client.ipfs.nodes
    geolocation_to_mdb(nodes_geolocation, ipfs_db)


def crawl_and_parse():
    pass


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
            node_info = ipfs_client.dht_findpeer(set_item, timeout=6)
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
            file_name_f.write(str(item) + "\n")
    file_name_f.close()


def iteratable_space_to_output(iteratable_space):
    """
    helper function for writing iteratable space's elements to output
    """
    for item in iteratable_space:
        print item


def geolocation(ips_set):
    """
    Geolocation function
    """
    geolocation_list = list() 
    for node_ip in ips_set:
        match = geolite2.lookup(node_ip)
        if match is not None:
            geolocation_list.append(match)
    return geolocation_list


def geolocation_to_mdb(geolocation_list, db):
    """
    Update location, ip and country to mongoDB ( do not insert new ones )
    """
    for node in geolocation_list:
        document = {"ip":node.ip,
                    "country":node.country,
                    "continent":node.continent,
                    "subdivisions":str(node.subdivisions),
                    "timezone":node.timezone,
                    "location":node.location}
        db.replace_one(document, document, upsert=True)


def get_location_from_mdb():
    pass
        

if __name__ == "__main__":
    main()


