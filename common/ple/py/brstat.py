import abc
import os
import sys, getopt
import argparse
import time

class Stat ():
    def __init__ (self, FName, CmpWithConstNum, CmpWithIntConstNum, CmpWithNoConstNum, CmpWithIntNoConstNum):
        self.FName = FName
        self.CmpWithConstNum      = CmpWithConstNum
        self.CmpWithIntConstNum   = CmpWithIntConstNum
        self.CmpWithNoConstNum    = CmpWithNoConstNum
        self.CmpWithIntNoConstNum = CmpWithIntNoConstNum

class BrStat ():  
    def __init__ (self, Path="cmp_statistic.info"):
        self.Path = Path
        self.Stats = []
        self.FuncNum  = 0
        self.TotalBrs = 0
        self.CmpWithConstNum = 0
        self.CmpWithIntConstNum = 0
        self.CmpWithNoConstNum  = 0
        self.CmpWithIntNoConstNum = 0
        self.LoadBrStats ()
             
    
    def LoadBrStats (self):
        with open(self.Path, 'r', encoding='latin1') as BrVF:
            for line in BrVF:
                Item = list (line.split (":"))
                FName                = Item[0]
                TotalBrs             = int (Item[1])
                CmpWithConstNum      = int (Item[2])
                CmpWithIntConstNum   = int (Item[3])
                CmpWithNoConstNum    = int (Item[4])
                CmpWithIntNoConstNum = int (Item[5])

                self.TotalBrs += TotalBrs
                self.CmpWithConstNum += CmpWithConstNum
                self.CmpWithIntConstNum += CmpWithIntConstNum
                self.CmpWithNoConstNum  += CmpWithNoConstNum
                self.CmpWithIntNoConstNum += CmpWithIntNoConstNum
                self.FuncNum += 1
                
                ST = Stat (FName, CmpWithConstNum, CmpWithIntConstNum, CmpWithNoConstNum, CmpWithIntNoConstNum)
                self.Stats.append (ST)

    def ShowStat (self):
        print ("===============================================")
        print ("===  CMP&SWITCHs: %4d              " %self.TotalBrs)
        print ("===  CMP&SWITCHs with Consts: %4d (%.2f)  " %(self.CmpWithConstNum, self.CmpWithConstNum*1.0/self.TotalBrs))
        print ("===  CMP&SWITCHs with No Consts: %4d (%.2f)  " %(self.CmpWithNoConstNum, self.CmpWithNoConstNum*1.0/self.TotalBrs))
        print ("===  CMP&SWITCHs with INT Consts: %4d (%.2f)  " %(self.CmpWithIntConstNum, self.CmpWithIntConstNum*1.0/self.TotalBrs))
        print ("===============================================\r\n")
    
def InitArgument (parser):
    parser.add_argument('--version', action='version', version='regrnl 1.0')
    
    grp = parser.add_argument_group('Main options', 'One of these (or --report) must be given')
    grp.add_argument('-o', '--offset', help='the offset of seed block')
                  
    parser.add_argument('filename', nargs='?', help='input file')
    parser.add_argument('arguments', nargs=argparse.REMAINDER, help='arguments to the program')


def main():
    parser = argparse.ArgumentParser()
    InitArgument (parser)

    opts = parser.parse_args()
    if opts.filename is None:
        parser.error('filename is missing: required with the main options')

    BS = BrStat (opts.filename)
    BS.ShowStat()

if __name__ == "__main__":
   main()
