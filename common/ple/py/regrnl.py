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


class Regression ():
    def __init__ (self, File, RegType):
        self.InputFile = File
        self.RegType   = RegType

    def Run (self):
        DF = pd.read_csv(self.InputFile, header=0)
        Headers = DF.columns.values
        X  = np.array (DF.loc[ :, Headers[0]]).reshape(-1, 1) # var-name = DF.columns[0]
        y  = np.array (DF.loc[ :, Headers[1]]) # var-name = DF.columns[1]
        print (X)
        print (y)
        
        # Fit regression model
        SVR_RBF    = SVR(kernel="rbf", C=100, gamma=0.1, epsilon=0.1)
        SVR_LINEAR = SVR(kernel="linear", C=100, gamma="auto")
        SCR_POLY   = SVR(kernel="poly", C=100, gamma="auto", degree=3, epsilon=0.1, coef0=1)

        SVRs     = [SVR_RBF, SVR_LINEAR, SCR_POLY]
        Kernals  = ["RBF", "Linear", "Polynomial"]
        MdColors = ["m", "c", "g"]

        lw = 2
        fig, axes = plt.subplots(nrows=1, ncols=3, figsize=(15, 10), sharey=True)
        for ix, svr in enumerate(SVRs):
            axes[ix].plot(
                X,
                svr.fit(X, y).predict(X),
                color=MdColors[ix],
                lw=lw,
                label="{} model".format(Kernals[ix]),
            )
            axes[ix].scatter(
                X[svr.support_],
                y[svr.support_],
                facecolor="none",
                edgecolor=MdColors[ix],
                s=50,
                label="{} support vectors".format(Kernals[ix]),
            )
            axes[ix].scatter(
                X[np.setdiff1d(np.arange(len(X)), svr.support_)],
                y[np.setdiff1d(np.arange(len(X)), svr.support_)],
                facecolor="none",
                edgecolor="k",
                s=50,
                label="other training data",
            )
            axes[ix].legend(
                loc="upper center",
                bbox_to_anchor=(0.5, 1.1),
                ncol=1,
                fancybox=True,
                shadow=True,
            )

        fig.text(0.5, 0.04, "data", ha="center", va="center")
        fig.text(0.06, 0.5, "target", ha="center", va="center", rotation="vertical")
        fig.suptitle("Support Vector Regression", fontsize=14)

        plt.title("Learning curve of %s" %(self.InputFile))
        plt.savefig(os.path.splitext(self.InputFile)[0] + ".png")
        plt.close()

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
    Reg = Regression (opts.filename, opts.type)
    Reg.Run()

if __name__ == "__main__":
   main()
