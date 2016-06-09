#!/usr/bin/env python
# -*- mode: python; coding: utf-8 -*-

"""
Utility for checking nodes up/down status
"""

import subprocess 


def pinger(id):
    """
    Returns latency status of the node. Average from 3 pings in miliseconds.
    """
    ping_status = subprocess.check_output(["ipfs", "ping", id, "-n", "3"])
    return ping_status.strip().split("\n")[-1].split(" ")[2]


def online_status(id):
    """
    Returns online/offline status of the node.
    """
    online_status = pinger(id)
    if online_status != 'error:' and online_status != 'dial':
        return online_status 
    else:
        return False 
