
cd CPython
rm -rf build
python setup.py build

cd -

lib=`find CPython/ -name "*x86_64-linux-gnu.so"`
cp $lib Python/PyDemo.so

python -m parser Python/
