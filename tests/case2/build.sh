
cd CPython
rm -rf build
python setup.py build

cd -
cp CPython/build/lib.linux-x86_64-3.7/PyDemo.cpython-37m-x86_64-linux-gnu.so Python/PyDemo.so

python -m parser Python/
