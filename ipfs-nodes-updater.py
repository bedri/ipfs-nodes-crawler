#!/usr/bin/env python
# -*- mode: python; coding: utf-8 -*-


"""
Parse mongodb and check if nodes status/info changed. If so - update with new one.
"""


from util.pinger import *
import pymongo


def main():
    test_id_true ="QmaWNCJuj9TEB6xYAL2qfXnV1ozY4VgtgpzeiQsSANy1cN"
    test_id_false ="QmaWNCJuj9TEB6xYAL2qfXnV1ozY4VgtgpzeiQsSANy1cd"
    online_status(test_id_false)


if __name__ == "__main__":
    main()
