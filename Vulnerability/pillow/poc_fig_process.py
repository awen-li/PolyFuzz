import sys
from PIL import Image
from PIL import ImageSequence

size = (128, 128)
box = (100, 100, 400, 400)


if __name__ == '__main__':
    try:
        im = Image.open(sys.argv[1])
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
    
