import os
import sys, getopt
import argparse
import time


InitTicks = time.time()

def TIME_COST (Name):
    print ("@@@@ ", Name, " time cost: ", str (time.time() - InitTicks))


def InitArgument (parser):
    parser.add_argument('--version', action='version', version='regrnl 1.0')
    
    grp = parser.add_argument_group('Main options', 'One of these (or --report) must be given')
    grp.add_argument('-t', '--type', help='regression type')
                  
    parser.add_argument('filename', nargs='?', help='input file')
    parser.add_argument('arguments', nargs=argparse.REMAINDER, help='arguments to the program')


def main():
    parser = argparse.ArgumentParser()
    InitArgument (parser)

    opts = parser.parse_args()
    if opts.filename is None:
        parser.error('filename is missing: required with the main options')

    print ("filename = " + opts.filename + ", regression type = " + opts.type)

if __name__ == "__main__":
   main()
