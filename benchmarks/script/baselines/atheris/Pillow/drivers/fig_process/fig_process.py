import sys
import atheris

with atheris.instrument_imports(key="PIL"):
    from PIL import Image
    from PIL import ImageSequence

size = (128, 128)
box = (100, 100, 400, 400)

seed_path = "seed.bin"

def WriteSeed (data):
    F = open (seed_path, "wb")
    F.write (data)
    F.close ()

@atheris.instrument_func    
def RunPillow ():
    im = None
    try:
        im = Image.open(seed_path)
        im.thumbnail(size)
        
        region = im.crop(box)
        region = region.transpose(Image.Transpose.ROTATE_180)
        im.paste(region, box)
        
        out = im.resize((128, 128))
        out = im.rotate(45)
        
        for frame in ImageSequence.Iterator(im):
            pass
            
        if im.mode != "RGB":
            im = im.convert("RGB")
    except Exception as e:
        print (e)
    
    return im

 
def RunTest (data):
    WriteSeed (data)
    im = RunPillow ()
    del im

if __name__ == '__main__':
    atheris.Setup(sys.argv, RunTest, enable_python_coverage=True)
    atheris.Fuzz()
    
