#!/usr/bin/env python
# -*- mode: python; coding: utf-8 -*-


def to_file(iteratable_space, file_name, mode):
    """
    helper function for writing iteratable space's elements to the file
    """
    for item in iteratable_space:
        with open(file_name, mode) as file_name_f:
            file_name_f.write("New item:\n")
            file_name_f.write(str(item) + "\n")
    file_name_f.close()


def to_output(iteratable_space):
    """
    helper function for writing iteratable space's elements to output
    """
    for item in iteratable_space:
        print item

