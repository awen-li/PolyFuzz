import contextlib
import re
import sys
from codecs import utf_8_decode
from collections import defaultdict
from bson import encode
from bson.raw_bson import RawBSONDocument
from bson.regex import Regex
from bson.codec_options import CodecOptions
from bson.objectid import ObjectId
from bson.son import SON
from pymongo import ASCENDING, DESCENDING, GEO2D, GEOSPHERE, HASHED, TEXT
from pymongo.bulk import BulkWriteError
from pymongo.collection import Collection, ReturnDocument
from pymongo.command_cursor import CommandCursor
from pymongo.cursor import CursorType
from pymongo.errors import ConfigurationError, DocumentTooLarge, DuplicateKeyError, ExecutionTimeout, InvalidDocument, InvalidName, InvalidOperation, OperationFailure, WriteConcernError
from pymongo.message import _COMMAND_OVERHEAD, _gen_find_command
from pymongo.mongo_client import MongoClient
from pymongo.operations import *
from pymongo.read_concern import DEFAULT_READ_CONCERN
from pymongo.read_preferences import ReadPreference
from pymongo.results import InsertOneResult, InsertManyResult, UpdateResult, DeleteResult
from pymongo.write_concern import WriteConcern

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
    data = eval(LoadInput (sys.argv[1]))
    try:
        res = db.test.create_indexes(data)
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

