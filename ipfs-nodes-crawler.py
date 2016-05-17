#!/usr/bin/env python
# -*- mode: python; coding: utf-8 -*-


"""IPFS nodes crawler"""
from util.iter_space import *
from geoip import geolite2
import sys
import json
import logging
import ipfsApi
import ipaddress
import subprocess
import pymongo


def main():
    """
    The main heartbeat
    """
    logging.basicConfig(format='%(asctime)s %(message)s',
                    datefmt='%Y%m%d %H%M%S',
                    filename='crawler.log',
                    level=logging.DEBUG)
    get_nodes_info_id()
#    default_crawler()
    


def default_crawler():
    ipfs_client = ipfsApi.Client('127.0.0.1', 5001)
    logging.info("RUNNING 'ipfs diag net'")
    ipfs_diag_net_output=ipfs_diag_net()
    logging.info("GETTING NODE IDs")
    nodes_ids_set = get_nodes_ids(ipfs_diag_net_output)
    logging.info("RUNNING THROUGH NODE IDs FOR INFO")
    nodes_info_list = get_nodes_info(nodes_ids_set, ipfs_client)
    ips_set = set()
    id_ips_dict = dict()
    
    mongo_client = pymongo.MongoClient()
    ipfs_db = mongo_client.ipfs.nodes


    for node_info in nodes_info_list:
        if node_info["Responses"] is not None:
            try:
                logging.info("GETTING NODE {ID:IPs} DICTIONARY")
                id_ips_dict = get_id_ips(node_info)
                if id_ips_dict is not None and len(id_ips_dict) > 0 and isinstance(id_ips_dict, dict):
                    logging.info("PARSING ALL IPS FROM NODE INFO")
                    for node_id, node_ips in id_ips_dict.iteritems():
                        logging.info("PARSING EXTERNAL IPs for %s", node_id)
                        set_tmp = set(node_ips)
                        node_ips = list(set_tmp)
                        for ip in node_ips:
                            logging.info("Checking %s", ip)
                            if not ipaddress.ip_address(unicode(ip)).is_private:
                                ips_set.add(ip)
                        id_ips_dict_new = ({node_id:ips_set})
                        ips_set =  set()
                    geolocation_list = geolocation(id_ips_dict_new[node_id])
                    if geolocation_list:
                        geolocation_to_mdb(geolocation_list, node_id,
                            id_ips_dict_new[node_id], ipfs_db)
            except:
                error = sys.exc_info()[0]
                logging.error("ERROR PROCESSING NODE INFO: %s", error)
    
 
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


def get_nodes_info_id():
    """
    From 'id <id>'
    subprocess.check_output 
    """
    
    mongo_client = pymongo.MongoClient()
    ipfs_db = mongo_client.ipfs.id2ip
    
    ipfs_client = ipfsApi.Client('127.0.0.1', 5001)
    ids_set = set(line.rstrip('\n') for line in open('nodes_ids'))
#    ips_set = set()
#    nodes_info_dict = dict()
    for _id in ids_set:
        ips_set = set()
        nodes_info_dict = dict()
        geolocation_list = list() 
        try:
            id_str = subprocess.check_output(["ipfs", "id", _id])
            id_json = json.loads(id_str)
            addresses = id_json["Addresses"]
            if isinstance(addresses, list):
                for _ip in addresses:
                    ip = _ip.split("/")[2]
                    if not ipaddress.ip_address(unicode(ip)).is_private:
                        ips_set.add(ip)
             
            nodes_info_dict = ({_id:ips_set})
            geolocation_list = geolocation(nodes_info_dict[_id])
            
            if geolocation_list:
               geolocation_to_mdb(geolocation_list, _id,
                                    nodes_info_dict[_id], ipfs_db)
            print nodes_info_dict
            print geolocation_list
        except:
            print sys.exc_info()[0]        




def get_nodes_info(node_ids_set, ipfs_client):
    """
    Returns list of raw info of the nodes, sometimes it gets string instead of dict, which is handled differently.
    From 'dht findpeer'
    """
    node_info_list = list()
    logging.info("SEARCHING NODE INFO ON DHT")
    for set_item in node_ids_set:
        logging.info("Parsing node %s", set_item)
        try:
            node_info = ipfs_client.dht_findpeer(set_item, timeout=10)
        except:
            error = sys.exc_info()[0]
            logging.error("ERROR PARSING DHT: %s", error)
        if isinstance(node_info, dict):
            node_info_list.append(node_info)
        elif isinstance(node_info, list):
            for list_item in node_info:
                node_info_list.append(list_item)
    return node_info_list


def parse_unicode_string(node_info):
    """
    Function to parse and create dicts from the unicode strings returned by ipfs net diag
    (this happens when multiple DHT nodes are traversed)
    Returns list of dicts

    update: not needed function? Reason: unicode output on new version is changed to list

    """
    node_info_list_d = list()
    for node in node_info.strip().split("\n"):
        node_json = json.loads(node)
        if node_json["Responses"]:
            logging.info("Node json from unicode: %s", node_json)
            node_info_list_d.append(node_json)
    return node_info_list_d

def get_id_ips(node_info):
    """
    Parsing IPs from the raw node info
    """
    ips_list = list()
    ips_set = set()
    id_ips_dict = dict()
    responses = node_info["Responses"]
    if len(responses) > 0 and responses != 'None':
        for i in range(0, len(responses)):
            for node_ip in responses[i]["Addrs"]:
                node_ip = node_ip.split("/")[2]
                ips_list.append(node_ip)
            node_id = responses[i]["ID"]
            set_tmp = set(ips_list)
            ips_list = list(set_tmp)
            id_ips_dict.update({node_id:ips_list})
            logging.info("Node ID and IPs: %s:%s", node_id, ips_list)
        return id_ips_dict
    else:
        return None


def geolocation(ips_set):
    """
    Geolocation function
    """
    geolocation_list = list()
    for node_ip in ips_set:
        logging.info("Getting geolocation object for IP %s", node_ip)
        match = geolite2.lookup(node_ip)
        if match is not None:
            geolocation_list.append(match)
    return geolocation_list


def geolocation_to_mdb(geolocation_list, node_id, ips_set, ipfs_db):
    """
    Update location, ip and country to mongoDB ( do not insert new ones )
    """
    for node in geolocation_list:
        logging.info("Writing data to mongoDB for %s", node.ip)
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
