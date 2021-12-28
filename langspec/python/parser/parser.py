#!/usr/bin/python

import os
import sys, getopt
import argparse
import time
from astwalk import GenPySummary
from astwalk import GenTestArgs


 
InitTicks = time.time()

def TIME_COST (Name):
    print ("@@@@ ", Name, " time cost: ", str (time.time() - InitTicks))


def ParseText (TxtFile):
    Content = []
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = Content + list (line.split ())
    return Content



def InitArgument (parser):
    parser.add_argument('--version', action='version', version='trace 2.0')
    
    grp = parser.add_argument_group('Main options', 'One of these (or --report) must be given')
    grp.add_argument('-t', '--test', help='parse the test cases of api name')
    grp.add_argument('-e', '--expression', action='store_true', help='the input is considered as a python expression')
    grp.add_argument('-E', '--exceptfile', help='the configure file for elimiate unnecesssay py files')
                     
    parser.add_argument('dirname', nargs='?', help='source dir to process')
    parser.add_argument('arguments', nargs=argparse.REMAINDER, help='arguments to the program')


def main():
    parser = argparse.ArgumentParser()
    InitArgument (parser)

    opts = parser.parse_args()
    if opts.dirname is None:
        parser.error('dirname is missing: required with the main options')

    if opts.test != None:
        GenTestArgs (opts.dirname, opts.test, opts.expression)
    else:
        ExpList = None
        if opts.exceptfile != None:
            ExpList = ParseText (opts.exceptfile)
        print (ExpList)
        GenPySummary (opts.dirname, ExpList)

    print ("Run successful.....")

if __name__ == "__main__":
   main()
