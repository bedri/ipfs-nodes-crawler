#!/usr/bin/env python
# -*- mode: python; coding: utf-8 -*-


"""IPFS nodes crawler"""
import sys
import logging
import ipfsApi
import ipaddress
import subprocess
import pymongo
from geoip import geolite2

def main():
    """
    The main heartbeat
    """
    logging.basicConfig(format='%(asctime)s %(message)s',
                    datefmt='%Y/%m/%d %H:%M:%S',
                    filename='crawler.log',
                    level=logging.DEBUG)
    ipfs_client = ipfsApi.Client('127.0.0.1', 5001)

    logging.info("Running 'ipfs diag net'")
    ipfs_diag_net_output=ipfs_diag_net()
    logging.info("Getting node IDs")
    nodes_ids_set = get_nodes_ids(ipfs_diag_net_output)
    logging.info("Running through node IDs for info")
    nodes_info_list = get_nodes_info(nodes_ids_set, ipfs_client)
    ips_set = set()
    id_ips_dict = dict()
    
    mongo_client = pymongo.MongoClient()
    ipfs_db = mongo_client.ipfs.nodes
   
    for node_info in nodes_info_list:
        try:
            logging.info("Getting node {ID:IPs} dictionary")
            id_ips_dict = get_id_ips(node_info)
            print id_ips_dict
            if len(id_ips_dict) > 0:
                logging.info("Parsing all IPs from node info")
                for node_id, node_ips in id_ips_dict.iteritems():
                    logging.info("Parsing external IPs")
                    for ip in node_ips:
                        if not ipaddress.ip_address(unicode(ip)).is_private:
                            ips_set.add(ip)
                    id_ips_dict_new = ({node_id:ips_set})
                    ips_set =  set()
                logging.info("Getting geolocation object")
                geolocation_list = geolocation(id_ips_dict_new[node_id])
                if geolocation_list:
                    logging.info("Writing node data to mongoDB")
                    geolocation_to_mdb(geolocation_list, node_id,
                        id_ips_dict_new[node_id], ipfs_db)
        except:
            logging.error("Error encountered")
            print sys.exc_info()[0]
         
     
    if nodes_ids_set: 
        iteratable_space_to_file(nodes_ids_set, "nodes_ids", "a")
    if ips_set:
        iteratable_space_to_file(ips_set, "nodes_ips", "a")
    if nodes_info_list:
        iteratable_space_to_file(nodes_info_list, "nodes_info", "a")
    
    """ 
    iteratable_space_to_output(nodes_ids_set)
    iteratable_space_to_output(ips_set)
    iteratable_space_to_output(nodes_info_list)
    """

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


def get_nodes_info(node_ids_set, ipfs_client):
    """
    Returns list of raw info of the nodes
    """
    node_info_list = list()
    logging.info("Searching node info on DHT")
    for set_item in node_ids_set:
        try:
            node_info = ipfs_client.dht_findpeer(set_item, timeout=10)
        except:
            logging.error("Error encountered")
            print sys.exc_info()[0]
        if node_info:
            node_info_list.append(node_info)
    return node_info_list


def get_id_ips(node_info):
    """
    Parsing IPs from the raw node info
    """
    ips_list = list()
    id_ips_dict = dict()
    responses = node_info["Responses"]
    if len(responses) > 0:
        for i in range(0, len(responses)):
            for node_ip in responses[i]["Addrs"]:
                node_ip = node_ip.split("/")[2]
                ips_list.append(node_ip)
            node_id = responses[i]["ID"]
            id_ips_dict.update({node_id:ips_list})
    return id_ips_dict


def iteratable_space_to_file(iteratable_space, file_name, mode):
    """
    helper function for writing iteratable space's elements to the file
    """
    for item in iteratable_space:
        with open(file_name, mode) as file_name_f:
            file_name_f.write("New item:\n")
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


def geolocation_to_mdb(geolocation_list, node_id, ips_set, ipfs_db):
    """
    Update location, ip and country to mongoDB ( do not insert new ones )
    """
    for node in geolocation_list:
        document = {"node_id":node_id,
                    "ips_set":str(ips_set),
                    "ip":node.ip,
                    "country":node.country,
                    "continent":node.continent,
                    "subdivisions":str(node.subdivisions),
                    "timezone":node.timezone,
                    "location":node.location}
        ipfs_db.replace_one(document, document, upsert=True)


def get_location_from_mdb():
    pass
        

def get_node_id_from_mdb():
    pass

if __name__ == "__main__":
    main()


