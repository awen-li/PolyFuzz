import sys
import ujson

def LoadInput (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content

if __name__ == '__main__':
    InputData = eval (LoadInput (sys.argv[1]))
    enc = ujson.dumps (InputData)
    dec = ujson.loads(enc)
