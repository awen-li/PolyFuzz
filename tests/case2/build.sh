
cd CPython
rm -rf build
python setup.py build

cd -
cp CPython/build/lib.linux-x86_64-3.9/PyDemo.cpython-39-x86_64-linux-gnu.so Python/PyDemo.so

python -m parser Python/
