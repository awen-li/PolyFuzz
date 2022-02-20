import abc
import os
import sys, getopt
import argparse
import time
import pandas as pd
import numpy as np
from sklearn.svm import SVR
import matplotlib.pyplot as plt


InitTicks = time.time()

def TIME_COST (Name):
    print ("@@@@ ", Name, " time cost: ", str (time.time() - InitTicks))

class BrValue ():
    def __init__ (self, Key, Type, Predict, Value):
        self.Key     = Key
        self.Type    = Type
        self.Pred    = Predict
        self.Values  = []
        self.Values.append (Value)

    def AddValue (self, Value):
        self.Values.append (Value)
        

class BrVSet ():
    def __init__ (self, Path="branch_vars.bv"):
        self.Path = Path
        self.BrVals = {}
        
        self.LoadBrVars ()
        self.Show ()

    def Show (self):
        for VKey, BV in self.BrVals.items ():
           print ("VrKey:%d, Type:%s, Pred:%d, Value: " %(VKey, BV.Type, BV.Pred), end="")
           print (BV.Values)
    
    def LoadBrVars (self):
        with open(self.Path, 'r', encoding='latin1') as BrVF:
            for line in BrVF:
                Item = list (line.split (":"))
                Key  = int (Item[0])
                Type = Item[1]
                Pred = int (Item[2])
                Value= int (Item[3])

                VrKey = int (str (Key) + str(Pred))
                Bv = self.BrVals.get (VrKey)
                if Bv == None:
                    self.BrVals[VrKey] = BrValue (Key, Type, Pred, Value)
                else:
                    Bv.AddValue (Value)
                

def Load (InputFile):
    DF = pd.read_csv(InputFile, header=0)
    DF = DF.sort_values(by=[DF.columns[0]])

    Headers = DF.columns.values
    X_Name = DF.columns[0]
    y_Name = DF.columns[1]
        
    X  = np.array (DF.loc[ :, Headers[0]]).reshape(-1, 1)
    y  = np.array (DF.loc[ :, Headers[1]])

    Len = int (len (X) * 0.8)
    X_Train = X [0:Len]
    y_Train = y [0:Len]
    X_Test  = X [Len:-1]
    y_Test  = y [Len:-1]

    return X_Name, y_Name, X_Train, y_Train, X_Test, y_Test

class RegrBase (metaclass=abc.ABCMeta):

    CList = [0.01, 0.1, 0.3, 0.5, 1, 5, 10, 20, 50, 100, 500, 1000, 2000, 5000]
    EpsnList = [0.01, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    GammaList = [0.01, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    Coef0List = [0.01, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 3, 5, 8, 10, 20, 50, 100]
    
    def __init__ (self, Kernal):
        self.Kernal    = Kernal
        self.Model     = None
        self.FitModel  = None
        self.FitC     = 0
        self.FitEpsn  = 0
        self.FitGamma = 0
        self.FitCoef0 = 0

    def SVs (self):
        return self.Model.support_

    @abc.abstractmethod
    def Fit (self):
        print ("[RegrBase] start to fit...")
        return 0
    
    def Predict (self, X):
        return self.FitModel.predict (X)
        

class RbfReg (RegrBase):
    def __init__ (self, Kernal):
        super(RbfReg, self).__init__(Kernal)
        self.Model    = None
        self.FitModel = None

    def Fit (self, X_Train, y_Train, X_Test, y_Test):
        Distance = 4294967200
        for C in RegrBase.CList:
            for epsilon in RegrBase.EpsnList:
                for gamma in RegrBase.GammaList:            
                    Model    = SVR(kernel="rbf", C=C, gamma=gamma, epsilon=epsilon)
                    FitModel = Model.fit (X_Train, y_Train)
                    Predicts = FitModel.predict (X_Test)
                    
                    CurDis   = 0
                    for ix in range(len (y_Test)):
                        CurDis += abs (y_Test[ix] - Predicts[ix])
                    
                    if CurDis < Distance:
                        self.Model    = Model
                        self.FitModel = FitModel
                        
                        self.FitC     = C
                        self.FitEpsn  = epsilon
                        self.FitGamma = gamma
                        
                        Distance = CurDis
        
        print ("[RbfReg]Min-Dis: %d, FitC:%f, FitEpsn:%f, FitGamma:%f" %(Distance, self.FitC, self.FitEpsn, self.FitGamma))
        return Distance

class PolyReg (RegrBase):
    def __init__ (self, Kernal):
        super(PolyReg, self).__init__(Kernal)
        self.Model    = None
        self.FitModel = None
        self.FitCoef0 = None

    def Fit (self, X_Train, y_Train, X_Test, y_Test):
        Distance = 4294967200
        for Coef0 in RegrBase.Coef0List:
            for epsilon in RegrBase.EpsnList:
                Model    = SVR(kernel="poly", epsilon=epsilon, coef0=Coef0)
                FitModel = Model.fit (X_Train, y_Train)
                Predicts = FitModel.predict (X_Test)
                        
                CurDis   = 0
                for ix in range(len (y_Test)):
                    CurDis += abs (y_Test[ix] - Predicts[ix])
                        
                if CurDis < Distance:
                    self.Model    = Model
                    self.FitModel = FitModel
                            
                    self.FitCoef0 = Coef0
                    self.FitEpsn  = epsilon

                    Distance = CurDis
        
        print ("[PolyReg]Min-Dis: %d, FitCoef0:%f, FitEpsn:%f" %(Distance, self.FitCoef0, self.FitEpsn))
        return Distance

class LinearReg (RegrBase):
    def __init__ (self,     Kernal):
        super(LinearReg, self).__init__(Kernal)
        self.Model    = None
        self.FitModel = None

    def Fit (self, X_Train, y_Train, X_Test, y_Test):
        Distance = 4294967200
        for C in RegrBase.CList:
            for epsilon in RegrBase.EpsnList:
                for gamma in RegrBase.GammaList:
                    Model    = SVR(kernel="linear", C=C, gamma=gamma, epsilon=epsilon)
                    FitModel = Model.fit (X_Train, y_Train)
                    Predicts = FitModel.predict (X_Test)

                    CurDis   = 0
                    for ix in range(len (y_Test)):
                        CurDis += abs (y_Test[ix] - Predicts[ix])
                        
                    if CurDis < Distance:
                        self.Model    = Model
                        self.FitModel = FitModel
                        
                        self.FitC     = C
                        self.FitEpsn  = epsilon
                        self.FitGamma = gamma
                        
                        Distance = CurDis

        print ("[LinearReg]Min-Dis: %d, FitC:%f, FitEpsn:%f, FitGamma:%f" %(Distance, self.FitC, self.FitEpsn, self.FitGamma))
        return Distance


def Plot (InputFile, SVRs, X_Name, y_Name, X_Train, y_Train, X_Test, y_Test):
    lw = 2
    MdColors = ["m", "c", "g"]
    fig, axes = plt.subplots(nrows=1, ncols=len(SVRs), figsize=(14, 6), sharey=True)
    for ix, svr in enumerate(SVRs):
        PredTrain = svr.Predict(X_Train)
        PredTest  = svr.Predict(X_Test)
        axes[ix].plot(
            X_Train,
            PredTrain,
            color=MdColors[ix],
            lw=lw,
            label="{} model".format(svr.Kernal),
        )
        axes[ix].scatter(
            X_Train[svr.SVs()],
            y_Train[svr.SVs()],
            facecolor="none",
            edgecolor=MdColors[ix],
            s=50,
            label="{} SVs".format(svr.Kernal),
        )
        axes[ix].scatter(
            X_Train[np.setdiff1d(np.arange(len(X_Train)), svr.SVs())],
            y_Train[np.setdiff1d(np.arange(len(X_Train)), svr.SVs())],
            facecolor="none",
            edgecolor="k",
            s=50,
            label="other training data",
        )
        axes[ix].plot(
            X_Test,
            PredTest,
            color='b',
            lw=lw,
            label="{} test predict".format(svr.Kernal),
        )
        axes[ix].scatter(
            X_Test,
            y_Test,
            facecolor="none",
            edgecolor='b',
            s=50,
            label="{} test data".format(svr.Kernal),
        )
        axes[ix].legend(
            loc="upper center",
            bbox_to_anchor=(0.5, 1.1),
            ncol=1,
            fancybox=True,
            shadow=True,
        )

    fig.text(0.5, 0.04, X_Name, ha="center", va="center")
    fig.text(0.06, 0.5, y_Name, ha="center", va="center", rotation="vertical")
    fig.suptitle("SVRs of " + InputFile, fontsize=14)

    plt.savefig(os.path.splitext(InputFile)[0] + ".png")
    plt.close()        


def RegMain (InputFile):
    X_Name, y_Name, X_Train, y_Train, X_Test, y_Test = Load (InputFile)
    if len (X_Train) == 0 or len (X_Test) == 0:
        return
    
    SvrRbf    = RbfReg ("Rbf")
    SvrPoly   = PolyReg ("Polynomial")
    SvrLinear = LinearReg ("Linear")
    
    SVRs = [SvrRbf, SvrPoly, SvrLinear]
    for svr in SVRs:
        svr.Fit (X_Train, y_Train, X_Test, y_Test)

    Plot (InputFile, SVRs, X_Name, y_Name, X_Train, y_Train, X_Test, y_Test)
    
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

    RegMain (opts.filename)
    BVS = BrVSet ()

if __name__ == "__main__":
   main()
