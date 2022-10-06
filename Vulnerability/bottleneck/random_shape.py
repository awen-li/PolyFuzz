import sys
import numpy as np
import bottleneck as bn


def LoadTest (FileName):
    with open(FileName, 'rb') as Fw:
        Value = Fw.read ()
        return Value


if __name__ == '__main__':
    try:
        Value  = bytearray (LoadTest (sys.argv[1]))
        Length = len (Value)
        if Length < 4:
            exit (0)
            
        CallFunc = sys.argv[2]
            
        print (Length)
        
        # 0b: dimenson
        d = Value[0]%8
        if d < 3:
            exit (0)
        if d > Length-1:
            d = Length-1
        print (d)
         
        # 0-Length-1: shape value   
        Shape = []
        for i in range(1, d+1):
            Sval = Value[i]%32
            if Sval == 0:
                Sval = 1
            Shape.append (Sval)
        
        print (Shape)
        
        Ary = np.random.random(tuple (Shape))
        eval(CallFunc)(Ary)

        R_Shape = []
        R_Shape.append (0)
        R_Shape.append (d-1)
        for i in range (1, d-1):
            R_Shape.append (i)
            
        print (R_Shape)
        
        R_Ary = Ary.transpose(tuple(R_Shape))
        eval(CallFunc)(R_Ary)

    except Exception as e:
        print (e)
