import abc
import os
import sys, getopt
import argparse
import time

class Stat ():
    def __init__ (self, FName, CmpWithConstNum, CmpWithIntConstNum, 
                      CmpWithNoConstNum, CmpWithIntNoConstNum, CmpWithPointerConstNum):
        self.FName = FName
        self.CmpWithConstNum      = CmpWithConstNum
        self.CmpWithIntConstNum   = CmpWithIntConstNum
        self.CmpWithNoConstNum    = CmpWithNoConstNum
        self.CmpWithIntNoConstNum = CmpWithIntNoConstNum
        self.CmpWithPointerConstNum = CmpWithPointerConstNum

class BrStat ():  
    def __init__ (self, Dir=None, Path=None):        
        self.Stats = []
        self.FuncNum  = 0
        self.TotalBrs = 0
        self.CmpWithConstNum = 0
        self.CmpWithIntConstNum = 0
        self.CmpWithNoConstNum  = 0
        self.CmpWithIntNoConstNum = 0
        self.CmpWithPointerConstNum = 0

        self.Path = []
        if Path != None:
            self.Path.append(Path)
        elif Dir != None:
            AllPaths = os.popen("find ./ -name cmp_statistic.info").read()
            self.Path = list (AllPaths.split ('\n'))
        else:
            return

        self.LoadBrStats ()  
    
    def LoadBrStats (self):
        for path in self.Path:
            if len (path) == 0:
                continue
            print ("Read statistic from %s" %path)
            with open(path, 'r', encoding='latin1') as BrVF:
                for line in BrVF:
                    Item = list (line.split (":"))
                    FName                = Item[0]
                    TotalBrs             = int (Item[1])
                    CmpWithConstNum      = int (Item[2])
                    CmpWithIntConstNum   = int (Item[3])
                    CmpWithNoConstNum    = int (Item[4])
                    CmpWithIntNoConstNum = int (Item[5])
                    CmpWithPointerConstNum = int (Item[6])

                    self.TotalBrs += TotalBrs
                    self.CmpWithConstNum += CmpWithConstNum
                    self.CmpWithIntConstNum += CmpWithIntConstNum
                    self.CmpWithNoConstNum  += CmpWithNoConstNum
                    self.CmpWithIntNoConstNum += CmpWithIntNoConstNum
                    self.CmpWithPointerConstNum += CmpWithPointerConstNum
                    self.FuncNum += 1
                    
                    ST = Stat (FName, CmpWithConstNum, CmpWithIntConstNum, CmpWithNoConstNum, CmpWithIntNoConstNum, CmpWithPointerConstNum)
                    self.Stats.append (ST)

    def ShowStat (self):
        print ("===============================================")
        print ("===  Functions: %4d              " %self.FuncNum)
        print ("===  CMP&SWITCHs: %4d              " %self.TotalBrs)
        print ("===  CMP&SWITCHs with Consts: %4d (%.3f)  " %(self.CmpWithConstNum, self.CmpWithConstNum*1.0/self.TotalBrs))
        print ("===  CMP&SWITCHs with No Consts: %4d (%.3f)  " %(self.CmpWithNoConstNum, self.CmpWithNoConstNum*1.0/self.TotalBrs))
        print ("===  CMP&SWITCHs with INT Consts: %4d (%.3f)  " %(self.CmpWithIntConstNum, self.CmpWithIntConstNum*1.0/self.TotalBrs))
        print ("===  CMP&SWITCHs with POINTER Consts: %4d (%.3f)  " %(self.CmpWithPointerConstNum, self.CmpWithPointerConstNum*1.0/self.TotalBrs))
        print ("===============================================\r\n")
    
def InitArgument (parser):
    parser.add_argument('--version', action='version', version='regrnl 1.0')
    
    grp = parser.add_argument_group('Main options', 'One of these (or --report) must be given')
    grp.add_argument('-d', '--directory', help='directory to compute statistic')
                  
    parser.add_argument('filename', nargs='?', help='input file')
    parser.add_argument('arguments', nargs=argparse.REMAINDER, help='arguments to the program')


def main():
    parser = argparse.ArgumentParser()
    InitArgument (parser)

    opts = parser.parse_args()
    if opts.filename != None:
        BS = BrStat (Path=opts.filename)
        BS.ShowStat()
    elif opts.directory != None:
        BS = BrStat (Dir=opts.directory)
        BS.ShowStat()
    else:
        parser.error('filename or directory is missing: required with the main options')


if __name__ == "__main__":
   main()
