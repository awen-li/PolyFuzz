#!/usr/bin/python

import os
import sys, getopt
import argparse
import time
import xml.dom.minidom
from xml.dom.minidom import parse
from astwalk import GenPySummary

 
InitTicks = time.time()

def TIME_COST (Name):
    print ("@@@@ ", Name, " time cost: ", str (time.time() - InitTicks))


def InitArgument (parser):
    parser.add_argument('--version', action='version', version='trace 2.0')
    
    grp = parser.add_argument_group('Main options', 'One of these (or --report) must be given')
    grp.add_argument('-b', '--branch', action='store_true',
                     help='extract branch variables by function ')
                     
    parser.add_argument('dirname', nargs='?', help='source dir to process')
    parser.add_argument('arguments', nargs=argparse.REMAINDER, help='arguments to the program')


def main():
    parser = argparse.ArgumentParser()
    InitArgument (parser)

    opts = parser.parse_args()
    if opts.dirname is None:
        parser.error('dirname is missing: required with the main options')
        
    GenPySummary (opts.dirname)

    print ("Run successful.....")

if __name__ == "__main__":
   main()
