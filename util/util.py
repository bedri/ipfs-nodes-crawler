#!/usr/bin/env python
# -*- mode: python; coding: utf-8 -*-


from iter_space import *


def dump2files(nodes_ids_set, ips_set, nodes_info_list):
    """
    Helper function, for writing data to files
    """
    if nodes_ids_set: 
        to_file(nodes_ids_set, "nodes_ids", "a")
    if ips_set:
        to_file(ips_set, "nodes_ips", "a")
    if nodes_info_list:
        to_file(nodes_info_list, "nodes_info", "a")


def address_list2address_set(address_list):
    """
    Helper function for parsing and converting address list to addres set
    """
    address_set = set()
    for address in address_list:
        address = address.split("/")[2]
        address_set.add(address)
    return address_set

