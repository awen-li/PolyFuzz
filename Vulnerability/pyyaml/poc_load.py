#!/usr/bin/python

import sys
import yaml


if __name__ == "__main__":
    with open (sys.argv[1], "rb") as bf:
        bytes = bf.read()
        context = yaml.load(bytes, Loader=yaml.FullLoader)
