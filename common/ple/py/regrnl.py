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

class Regression (metaclass=abc.ABCMeta):
    def __init__ (self, Kernal):
        self.Kernal    = Kernal
        self.Model     = None
        self.FitModel  = None

    def SVs (self):
        return self.Model.support_
    
    def Predict (self, X):
        return self.FitModel.predict (X)
        

class RbfReg (Regression):
    def __init__ (self, Kernal, X_Train, y_Train, C=100):
        super(RbfReg, self).__init__(Kernal)
        self.Model    = SVR(kernel="rbf", C=C)
        self.FitModel = self.Model.fit (X_Train, y_Train)

class PolyReg (Regression):
    def __init__ (self, Kernal, X_Train, y_Train, Coef0=3):
        super(PolyReg, self).__init__(Kernal)
        self.Model    = SVR(kernel="poly", coef0=Coef0)
        self.FitModel = self.Model.fit (X_Train, y_Train)

class LinearReg (Regression):
    def __init__ (self,     Kernal, X_Train, y_Train):
        super(LinearReg, self).__init__(Kernal)
        self.Model    = SVR(kernel="linear")
        self.FitModel = self.Model.fit (X_Train, y_Train)


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
    
    SvrRbf    = RbfReg ("Rbf", X_Train, y_Train, 1000)
    SvrPoly   = PolyReg ("Polynomial", X_Train, y_Train, 3)
    SvrLinear = LinearReg ("Linear", X_Train, y_Train)

    Plot (InputFile, [SvrRbf, SvrPoly, SvrLinear], X_Name, y_Name, X_Train, y_Train, X_Test, y_Test)
    
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

if __name__ == "__main__":
   main()
