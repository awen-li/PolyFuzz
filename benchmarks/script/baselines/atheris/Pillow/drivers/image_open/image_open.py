import sys
from io import BytesIO
import atheris

with atheris.instrument_imports():
    from PIL import Image

@atheris.instrument_func    
def RunPillow (Data):
    try:
        with Image.open(BytesIO(Data)):
            pass      
    except Exception as e:
        print (e)
    
if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()
    
