
import sys
from pymongo.uri_parser import (parse_userinfo,
                                split_hosts,
                                split_options,
                                parse_uri)
import pyprob


pyprob.Setup('py_summary.xml')

def ParseText (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content

if __name__ == '__main__':
    url = ParseText (sys.argv[1])
    try:
        res = parse_uri(url)
        #print (res)
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)