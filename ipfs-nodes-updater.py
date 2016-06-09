#!/usr/bin/env python
# -*- mode: python; coding: utf-8 -*-


"""
Parse mongodb and check if nodes status/info changed. If so - update with new one.
"""


from util.pinger import *
import pymongo


def iterate_and_update_ids(ipfs_db):
    """
    Iterates through all docs, pings node_id, and updates with offline/online(latency in ms) data.
    """
    cursor = ipfs_db.find(modifiers={"$snapshot": True})
    for result in cursor:
        _id = result["node_id"]
        print "ID:" + _id 
        print online_status(_id)
    cursor.close()


def main():
    """
    Main heartbeat
    """
    mongo_client = pymongo.MongoClient()
    ipfs_db = mongo_client.ipfs.id2ip
    iterate_and_update_ids(ipfs_db)


if __name__ == "__main__":
    main()
