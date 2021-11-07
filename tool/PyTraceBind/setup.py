
import os
import shutil
import subprocess
import sys
import tempfile

import setuptools
from setuptools import Extension
from setuptools import setup

__version__ = os.getenv("PYINS_VERSION", "1.0.0")


class PybindHeader(object):
  def __str__(self):
    import pybind11
    return pybind11.get_include()

ext_modules = [
    Extension(
        "pyins",
        sorted([
            "pyins.cpp",
            "trace.cpp",
        ]),
        include_dirs=[
            PybindHeader(),
        ],
        language="c++"),
]


setup(
    name="pyins",
    version=__version__,
    author="Wen Li",
    author_email="li.wen@wsu.edu",
    url="https://github.com/Daybreak2019/xFuzz",
    description="demo for python profile",
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    ext_modules=ext_modules,
    setup_requires=["pybind11>=2.5.0"],
)
