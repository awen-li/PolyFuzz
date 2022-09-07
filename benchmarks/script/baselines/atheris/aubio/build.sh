

export ROOT=`cd ../../../../ && pwd`
export target=aubio

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/aubio/aubio.git
	
	pushd $target
	
	LD_CLANG="$(python -c "import sysconfig; print(sysconfig.get_config_var('LDSHARED'))")"	
	LD_CLANG=`echo $LD_CLANG | sed 's/^gcc/clang/'`
	
	export LDSHARED=$LD_CLANG
	export CC="clang" CFLAGS="-fsanitize=fuzzer-no-link" CXX="clang++" CXXFLAGS="-fsanitize=fuzzer-no-link"

	pip install .

	popd
}

# 1. compile the C unit
cd $ROOT
compile

