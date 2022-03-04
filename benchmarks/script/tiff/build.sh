

target=tiff
task=$1
ROOT=`pwd`

BenchDir=../../C-benchs/
cd $BenchDir
tar -zxvf $target.tar.gz

cd $target
./configure --prefix=/root/anaconda3/
make clean && make CC=afl-cc CXX=afl-cc && make install

cd $ROOT
ple -s ./seeds -d . -B $BenchDir
