import sys
import io
from absl.testing import absltest
from absl.testing.absltest import mock
from tink.streaming_aead import _file_object_adapter
import pyprob

pyprob.Setup('py_summary.xml', 'es_write.py')

def partial_write (raw_data):
    file_object = mock.Mock()
    file_object.write = mock.Mock(wraps=lambda data: len(data) - 1)
    adapter = _file_object_adapter.FileObjectAdapter(file_object)
    for i in range (64):   
        adapter.write(raw_data)
    
def basic_write (raw_data):
    file_object = io.BytesIO()
    adapter = _file_object_adapter.FileObjectAdapter(file_object)
    for i in range (64):   
        adapter.write(raw_data)

def LoadInput (TxtFile):
    Content = ""
    with open(TxtFile, 'r', encoding='latin1') as txfile:
        for line in txfile:
            Content = line.replace("\n", "")
            break
    return Content  

if __name__ == '__main__':
    try:
        raw_data = eval (LoadInput (sys.argv[1]))
        basic_write (raw_data)
        partial_write (raw_data)
        
    except Exception as e:
        pyprob.PyExcept (type(e).__name__, __file__, e.__traceback__.tb_lineno)

