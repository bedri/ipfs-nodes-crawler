#!/usr/bin/env python
# -*- mode: python; coding: utf-8 -*-


"""IPFS nodes crawler"""
from util.iter_space import *
import sys
import json
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
        print type(node_info)
        print "NODE INFO:"
        print node_info
        try:
            logging.info("Getting node {ID:IPs} dictionary")
            id_ips_dict = get_id_ips(node_info)
            if len(id_ips_dict) > 0 and isinstance(id_ips_dict, dict):
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
            log_error = "Error processing node info"
            logging.error(log_error)
            print sys.exc_info()[0]
         
     
    if nodes_ids_set: 
        to_file(nodes_ids_set, "nodes_ids", "a")
    if ips_set:
        to_file(ips_set, "nodes_ips", "a")
    if nodes_info_list:
        to_file(nodes_info_list, "nodes_info", "a")
    

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
    Returns list of raw info of the nodes, sometimes it gets string instead of dict, which is handled differently.
    """
    node_info_list = list()
    logging.info("Searching node info on DHT")
    for set_item in node_ids_set:
        try:
            node_info = ipfs_client.dht_findpeer(set_item, timeout=10)
        except:
            logging.error("Error parsing DHT")
            print sys.exc_info()[0]
        if isinstance(node_info, dict):
            node_info_list.append(node_info)
        elif isinstance(node_info, unicode):
            pass
            #node_info_list_d = parse_unicode_string(node_info)
            #for node_info_dict in node_info_list_d:
            #    node_info_list.append(node_info_dict)
    return node_info_list


def parse_unicode_string(node_info):
    """
    Function to parse and create dicts from the unicode strings returned by ipfs net diag
    (this happens when multiple DHT nodes are traversed)
    Returns list of dicts
    """
    node_info_list_d = list()
    for node in node_info.strip().split("\n"):
        node_json = json.loads(node)
        if node_json["Responses"]:
           node_info_list_d.append(node_json)
    return node_info_list_d


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
#                    "ips_set":str(ips_set),
                    "ip":node.ip,
                    "country":node.country,
                    "continent":node.continent,
                    "subdivisions":str(node.subdivisions),
                    "timezone":node.timezone,
                    "location":node.location}
        ipfs_db.replace_one(document, document, upsert=True)


if __name__ == "__main__":
    main()
