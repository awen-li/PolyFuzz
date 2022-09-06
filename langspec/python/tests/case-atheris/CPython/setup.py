#!/usr/bin/python

import os
from distutils.core import setup, Extension

os.environ["CC"]  = "clang"
os.environ["CXX"] = "clang++"
os.environ["CFLAGS"] = "-fsanitize=address"
os.environ["CXXFLAGS"] = "-fsanitize=address"


module1 = Extension('PyDemo',
                    define_macros = [('MAJOR_VERSION', '1'), ('MINOR_VERSION', '0')],
                    extra_link_args=['-lxFuzztrace'],
                    #extra_compile_args=[]
                    include_dirs = ['../C/include'],
                    #libraries = ['DemoTrace'],
                    #library_dirs = ['/usr/lib'],
                    sources = ['Demo.c', '../C/source/Passwd.c'])

setup (name = 'PyDemo',
       version = '1.0',
       description = 'package for python tracing',
       author = 'Wen xx',
       author_email = 'xx.wen@xxx.edu',
       ext_modules = [module1])

