import sys
from io import BytesIO
import atheris

with atheris.instrument_imports():
    from PIL import Image


@atheris.instrument_func    
def RunPillow (Data):
    try:
        with Image.open(BytesIO(Data)) as im:
            im.load()
            test_output = BytesIO()
            im.save(test_output, "JPEG2000")
            test_output.seek(0)
            test_output.read()
        
    except Exception as e:
        print (e)
    
if __name__ == '__main__':
    atheris.Setup(sys.argv, RunPillow, enable_python_coverage=True)
    atheris.Fuzz()
    
