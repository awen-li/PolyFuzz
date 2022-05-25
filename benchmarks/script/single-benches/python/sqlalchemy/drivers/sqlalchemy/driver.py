
import sys
import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy import Table, Column, Integer, String, MetaData
from sqlalchemy.sql import text

import pyprob

pyprob.Setup('py_summary.xml', 'driver.py')

def LoadBytes (FName):
    bytes = None
    with open (FName, "rb") as bf:
        bytes = bf.read()
    return bytes

if __name__ == "__main__":
    try:
        input_bytes = LoadBytes (sys.argv[1])
        
        sql_string = input_bytes.decode("utf-8")
        metadata = MetaData()
        fuzz_table = Table('fuzz_table', metadata,
          Column('id', Integer, primary_key=True),
          Column('column1', String),
          Column('column2', String),
        )

        engine = create_engine('sqlite:///fuzz.db')
        metadata.create_all(engine)
        statement = text(sql_string)
        with engine.connect() as conn:            
            conn.execute(statement)
    except Exception as e:
        print (e)
