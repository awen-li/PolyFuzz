

export ROOT=`cd ../../../../ && pwd`
export target=tink

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/google/tink.git
	
	Protoc=`which protoc`
	if [ ! -n "$Protoc" ]; then
	    apt install -y protobuf-compiler
	    pip install google
	    pip install protobuf
	fi

	pushd $target/python
	
	LD_CLANG="$(python -c "import sysconfig; print(sysconfig.get_config_var('LDSHARED'))")"	
	LD_CLANG=`echo $LD_CLANG | sed 's/^gcc/clang/'`
	
	export LDSHARED=$LD_CLANG
	export CC="clang" CFLAGS="-fsanitize=fuzzer-no-link" CXX="clang++" CXXFLAGS="-fsanitize=fuzzer-no-link"
	
	cp $ROOT/script/$target/setup.py ./
	pip3 install .

	popd	
}


cd $ROOT && compile
