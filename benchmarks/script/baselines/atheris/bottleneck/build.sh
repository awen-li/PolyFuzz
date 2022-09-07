

export ROOT=`cd ../../../../ && pwd`
export target=bottleneck


function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/pydata/bottleneck.git
	
	pushd $target
	
	LD_CLANG="$(python -c "import sysconfig; print(sysconfig.get_config_var('LDSHARED'))")"	
	LD_CLANG=`echo $LD_CLANG | sed 's/^gcc/clang/'`
	
	export LDSHARED=$LD_CLANG
	export CC="clang" CFLAGS="-fsanitize=fuzzer-no-link" CXX="clang++" CXXFLAGS="-fsanitize=fuzzer-no-link"
	
	pip3 install .
	
	popd
}


cd $ROOT
compile
