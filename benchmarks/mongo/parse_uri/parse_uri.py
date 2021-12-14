import copy
import sys
import warnings
from urllib.parse import quote_plus
from bson.binary import JAVA_LEGACY
from pymongo import ReadPreference
from pymongo.errors import ConfigurationError, InvalidURI
from pymongo.uri_parser import parse_userinfo, split_hosts, split_options, parse_uri

import sys
import pyprob


pyprob.Setup('py_summary.xml')

def LoadInput (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content

if __name__ == '__main__':
    data = (LoadInput (sys.argv[1]))
    try:
        res = parse_uri(data)
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

