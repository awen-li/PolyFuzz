
import os
import shutil
import subprocess
import sys
import tempfile

import setuptools
from setuptools import Extension
from setuptools import setup

#os.environ["CC"]  = "clang"
#os.environ["CXX"] = "clang"

class PybindHeader(object):
  def __str__(self):
    import pybind11
    return pybind11.get_include()

ext_modules = [
    Extension(
        "pyprob",     
        sorted([
            "src/setup.cpp",
            "src/except.cpp",
            "src/op_code.cpp",
            "src/loadbrval.cpp",
            "src/pyprob.cpp",
            "src/pytrace.cpp",
        ]),
        include_dirs=[
            "include",
            "/usr/include/ctrace",
            PybindHeader(),
        ],
        extra_compile_args=["-O3",
                            "-D_PROB_DATA_",
                            #"-D__DEBUG__"
                           ],
        extra_link_args=["-lmxml", "-lxFuzztrace"],
        language="c++"),
]

os

setup(
    name="pyprob",
    version="1.0.0",
    author="Wen Li",
    author_email="li.wen@wsu.edu",
    url="https://github.com/Daybreak2019/xFuzz",
    description="dynamic prob for python",
    ext_modules=ext_modules,
    setup_requires=["pybind11>=2.5.0"],
)
