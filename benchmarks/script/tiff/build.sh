

target=tiff
task=$1
ROOT=`pwd`

BenchDir=../../C-benchs/
cd $BenchDir
tar -zxvf $target.tar.gz

cd $target
find ./ -name branch_vars.bv | xargs rm -rf
find ./ -name cmp_statistic.info | xargs rm -rf
./configure --prefix=/root/anaconda3/
make clean && make CC=afl-cc CXX=afl-cc && make install

cd $ROOT
ple -s ./seeds -d . -B $BenchDir/$target
