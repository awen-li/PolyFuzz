import site; 
import os
import glob
for f in glob.glob(os.path.join(site.getsitepackages()[0], "jep/libjep.*")):
    print(f)
