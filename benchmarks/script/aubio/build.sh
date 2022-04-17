

export ROOT=`cd ../../ && pwd`
export target=aubio

function deps ()
{
    apt-get install ffmpeg 
}

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target
	fi
	
	git clone https://github.com/aubio/aubio.git
	
	pushd $target
	
	export CC="afl-cc -lxFuzztrace"
	export CXX="afl-c++"
	
	export AFL_TRACE_DU_SHUTDOWN=1
	make
	cp build/src/libaubio* /usr/lib/
	
	#python setup.py install
	pip install -v .
	unset AFL_TRACE_DU_SHUTDOWN
	popd
}

# 1. compile the C unit
cd $ROOT
compile

# 2. summarize the Python unit
PyDir=$target/python
python -m parser $PyDir
cp $PyDir/py_summary.xml $ROOT/script/$target/
