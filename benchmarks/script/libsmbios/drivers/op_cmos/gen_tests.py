import sys
import random

pageunit = 4096
char_set = ['a', 'b', 'c', 'd', 'e', 'f', 'g', '0', '1', '2', '3', '4', '5', ',', ';', '[', '}', '/', '%', '@', '\t', '\r']
char_len = len (char_set)

tIndex = 0
for ps in range (32):
    TF = 'tests/test-' + str (tIndex)
    tIndex += 1
    pagesize = pageunit * (ps+1)
    print ("pagesize = %d, gen test %s" %(pagesize, TF))
    
    fd = open(TF, "w+")
    for i in range(pagesize*4 + 1):
        if tIndex%2 == 0:
            index = random.randint (0, char_len-1)
            fd.write(char_set[index])
        else:
            fd.write("j")
    fd.close()

