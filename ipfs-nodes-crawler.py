#!/usr/bin/env python
# -*- mode: python; coding: utf-8 -*-


"""IPFS nodes crawler"""
from util.pinger import *
from util.util import *
from geoip import geolite2
import sys
import json
import logging
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
    crawler()

    
 

def ipfs_diag_net():
    """
    Gets raw output from:
    ipfs diag net
    """
    return subprocess.check_output(["ipfs", "diag", "net"])


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



def crawler():
    """
    From 'id <id>'
    subprocess.check_output(["ipfs", "id", _id]) 
    """
    logging.info("Running \'ipfs diag net\'")
    ipfs_diag_net_output=ipfs_diag_net()
    logging.info("Getting nodes IDs")
    nodes_ids_set = get_nodes_ids(ipfs_diag_net_output)
    logging.info("Found %s IDs", len(nodes_ids_set)) 
    mongo_client = pymongo.MongoClient()
    ipfs_db = mongo_client.ipfs.id2ip
    
    for _id in nodes_ids_set:
        ips_set = set()
        nodes_info_dict = dict()
        geolocation_list = list() 
        try:
            logging.info("Getting node info with \'ipfs id %s\'", _id)
            #todo: multithreading
            id_str = subprocess.check_output(["ipfs", "id", _id])
            id_json = json.loads(id_str)
            addresses = id_json["Addresses"]
            if isinstance(addresses, list):
                addresses_set = address_list2address_set(addresses)
                logging.info("Iterating through IPs %s", addresses_set)
                for ip in addresses_set:
                    logging.info("Checking IP %s ", ip)
                    if not ipaddress.ip_address(unicode(ip)).is_private:
                        ips_set.add(ip)
            else:
                logging.info("Did not got info from %s. Probably \'null\' address list.", _id)
            nodes_info_dict = ({_id:ips_set})
            geolocation_list = geolocation(nodes_info_dict[_id])
            if geolocation_list:
                geolocation_to_mdb(geolocation_list, _id, nodes_info_dict[_id],
                                id_json["AgentVersion"], id_json["ProtocolVersion"],
                                id_json["PublicKey"], ipfs_db)
        except:
            error = sys.exc_info()
            logging.error("Error processing node %s: %s", _id, error)



def geolocation(ips_set):
    """
    Geolocation function
    """
    geolocation_list = list()
    for node_ip in ips_set:
        logging.info("Getting geolocation object for external IP %s", node_ip)
        match = geolite2.lookup(node_ip)
        if match is not None:
            geolocation_list.append(match)
    return geolocation_list


def geolocation_to_mdb(geolocation_list, node_id, ips_set, agent_version,
                        protocol_version, public_key, ipfs_db):
    """
    Update location, ip and country and other info to mongoDB ( do not insert new ones )
    """
    for node in geolocation_list:
        logging.info("Writing data to mongoDB for %s", node.ip)
        document = {"node_id":node_id,
#                    "ips_set":str(ips_set),
                    "ip":node.ip,
                    "agent_version":agent_version,
                    "protocol_version":protocol_version,
                    "public_key":public_key,
                    "country":node.country,
                    "continent":node.continent,
                    "subdivisions":str(node.subdivisions),
                    "timezone":node.timezone,
                    "location":node.location}
        ipfs_db.replace_one(document, document, upsert=True)


if __name__ == "__main__":
    main()
