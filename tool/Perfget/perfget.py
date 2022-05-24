import abc
import os
import sys, getopt
import argparse
import time

class Stat ():
    def __init__ (self, FName, PathNum, BlockNum, BugNum):
        self.FName     = FName
        self.PathNum   = PathNum
        self.BlockNum  = BlockNum
        self.BugNum    = BugNum


class PerfStat ():  
    def __init__ (self, Dir=None):        
        self.Stats = []
        self.Dirs  = []
        self.DriverNum  = 0
        self.TotalPathNum = 0
        self.TotalBlockNum = 0
        self.TotalBugNum = 0
        
        AllDir = []
        if Dir == None:
            self.DirPath = "./"
            AllDir = os.popen("ls ./").read()
        else:
            self.DirPath = Dir
            AllDir = os.popen("ls " + Dir).read()
        self.Dirs = list (AllDir.split ('\n'))
        print (self.Dirs)

        self.LoadBrStats ()  
    
    def LoadBrStats (self):
        for drv in self.Dirs:
            if len (drv) == 0:
                continue
                
            FilePath = self.DirPath + drv + "/fuzz/" + "perf_periodic.txt"
            if not os.path.exists (FilePath):
                continue
            
            print ("Read per-metric from %s" %drv)
            with open(FilePath, 'r', encoding='latin1') as pf:
                lines = pf.readlines()
                last_line = lines[-1]
                
                Item = list (last_line.split (","))
                TimeStamp  = str (Item[0])
                PathNum    = int (Item[1])
                BlockNum   = int (Item[2])
                BugNum     = int (Item[3])

                self.TotalPathNum  += PathNum
                self.TotalBlockNum += BlockNum
                self.TotalBugNum   += BugNum
                    
                ST = Stat (drv, PathNum, BlockNum, BugNum)
                self.Stats.append (ST)

    def ShowStat (self):
        print ("===============================================")
        print ("===  Drivers:  %4d        " %len(self.Stats))
        print ("===  PathNum:  %4d        " %self.TotalPathNum)
        print ("===  BlockNum: %4d        " %self.TotalBlockNum)
        print ("===  BugNum:   %4d        " %self.TotalBugNum)
        print ("===============================================\r\n")
    
def InitArgument (parser):
    parser.add_argument('--version', action='version', version='regrnl 1.0')
                  
    parser.add_argument('dirname', nargs='?', help='input file')
    parser.add_argument('arguments', nargs=argparse.REMAINDER, help='arguments to the program')


def main():
    parser = argparse.ArgumentParser()
    InitArgument (parser)

    opts = parser.parse_args()
    if opts.dirname != None:
        ps = PerfStat (Dir=opts.dirname)
        ps.ShowStat()
    else:
        parser.error('directory is missing: required with the main options')


if __name__ == "__main__":
   main()
