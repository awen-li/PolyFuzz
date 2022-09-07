#!/bin/bash  
  
Root=`pwd`
CurCase=`basename $Root`

echo $CurCase

cd ../

LD_CLANG="$(python -c "import sysconfig; print(sysconfig.get_config_var('LDSHARED'))")"	
LD_CLANG=`echo $LD_CLANG | sed 's/^gcc/clang/'`
	
export LDSHARED=$LD_CLANG
export CC="clang" CFLAGS="-fsanitize=fuzzer-no-link" CXX="clang++" CXXFLAGS="-fsanitize=fuzzer-no-link"

./build.sh $CurCase

cd -