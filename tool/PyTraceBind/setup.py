
import os
import shutil
import subprocess
import sys
import tempfile

import setuptools
from setuptools import Extension
from setuptools import setup
from setuptools.command.build_ext import build_ext

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


class BuildExt(build_ext):
  """A custom build extension for adding compiler-specific options."""

  def build_extensions(self):

    for ext in self.extensions:
      ext.define_macros = [("VERSION_INFO",
                            "'{}'".format(self.distribution.get_version())),
                           ("ATHERIS_MODULE_NAME", ext.name)]
      ext.extra_compile_args = c_opts
      if ext.name == "atheris_no_libfuzzer":
        ext.extra_link_args = l_opts
      else:
        ext.extra_link_args = l_opts + [libfuzzer]
    build_ext.build_extensions(self)

    try:
      self.deploy_file(libfuzzer, orig_libfuzzer_name)
    except Exception as e:
      sys.stderr.write(str(e))
      sys.stderr.write("\n")
      pass


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
