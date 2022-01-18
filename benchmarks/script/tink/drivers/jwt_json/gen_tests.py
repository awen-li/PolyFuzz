import sys

size = 128

def gen_count ():
    seed = "\'{"
    for x in range (size):
        key = str (x)
        value = str (x)   
        seed += "\"" + key + "\":" + value
        if x < size-1:  
            seed += ","

    seed += "}\'"
    print (seed)

    fd = open("test-c", "w+")
    fd.write(seed)
    fd.close()
    
def gen_size ():
    seed = "\'{"
    key  = ""
    value = ""
    for x in range (size):
        key += str (x)
        value += str (x)   
    seed += "\"" + key + "\":" + value + "}\'"
    print (seed)

    fd = open("test-s", "w+")
    fd.write(seed)
    fd.close()
 
gen_count ()   
gen_size ()